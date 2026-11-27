package cmd

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cf"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/unifi"
)

type groupSyncer interface {
	SyncGroup(ctx context.Context, members []string) error
}

// blocklistCoordinator merges every account's ranked IPs into one UniFi group.
type blocklistCoordinator struct {
	mu        sync.Mutex
	byAccount map[string][]string
	order     []string
	published bool
	client    groupSyncer
}

func (c *blocklistCoordinator) Publish(accountID string, ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byAccount == nil {
		c.byAccount = make(map[string][]string)
	}
	if _, seen := c.byAccount[accountID]; !seen {
		c.order = append(c.order, accountID)
	}
	c.byAccount[accountID] = append([]string(nil), ips...)
	c.published = true
}

func (c *blocklistCoordinator) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, accountID := range c.order {
		for _, ip := range c.byAccount[accountID] {
			if _, duplicate := seen[ip]; duplicate {
				continue
			}
			seen[ip] = struct{}{}
			result = append(result, ip)
		}
	}
	return result
}

func (c *blocklistCoordinator) Sync(ctx context.Context) error {
	if c.client == nil {
		return nil
	}
	c.mu.Lock()
	ready := c.published
	c.mu.Unlock()
	if !ready {
		return nil
	}
	return c.client.SyncGroup(ctx, c.snapshot())
}

const (
	DEFAULT_CONFIG_PATH = "/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml"
	name                = "crowdsec-cloudflare-bouncer"
)

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return fmt.Errorf("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return fmt.Errorf("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func newAPILogger(logDir string, logAPIRequests *bool) (*log.Logger, error) {
	APILogger := log.New()
	if *logAPIRequests {
		f, err := os.OpenFile(
			filepath.Join(logDir, "crowdsec-cloudflare-bouncer-api-calls.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		APILogger.SetOutput(f)
		APILogger.Level = log.DebugLevel
	} else {
		APILogger.SetOutput(io.Discard)
	}
	return APILogger, nil
}

func Execute() error {
	// Create go routine per cloudflare account
	// By using channels, after every nth second feed the decisions to each cf routine.
	// Each cf routine maintains it's own IP list and cache.

	configTokens := flag.String("g", "", "comma separated tokens to generate config for")
	configOutputPath := flag.String("o", "", "path to store generated config to")
	configPath := flag.String("c", "", "path to config file")
	onlySetup := flag.Bool("s", false, "only setup the ip lists and rules for cloudflare and exit")
	delete := flag.Bool("d", false, "delete IP lists and firewall rules which are created by the bouncer")
	ver := flag.Bool("version", false, "Display version information and exit")
	logAPIRequests := flag.Bool("lc", false, "logs API requests")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *ver {
		fmt.Print(version.FullString())
		return nil
	}

	if *delete && *onlySetup {
		return fmt.Errorf("conflicting cli arguments, pass only one of '-d' or '-s'")
	}

	if configPath == nil || *configPath == "" {
		*configPath = DEFAULT_CONFIG_PATH
	}

	if configTokens != nil && *configTokens != "" {
		cfgTokenString, err := cfg.ConfigTokens(*configTokens, *configPath)
		if err != nil {
			return err
		}
		if configOutputPath != nil && *configOutputPath != "" {
			err := os.WriteFile(*configOutputPath, []byte(cfgTokenString), 0664)
			if err != nil {
				return err
			}
			log.Printf("Config successfully generated in %s", *configOutputPath)
		} else {
			fmt.Print(cfgTokenString)
		}
		return nil
	}

	configBytes, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configBytes))
		return nil
	}

	conf, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to parse config: %w", err)
	}

	if *delete || *onlySetup {
		log.SetOutput(os.Stdout)
	}

	APILogger, err := newAPILogger(conf.Logging.LogDir, logAPIRequests)
	if err != nil {
		return err
	}

	var csLAPI *csbouncer.StreamBouncer

	g, ctx := errgroup.WithContext(context.Background())
	var coordinator *blocklistCoordinator
	if conf.Unifi.Enabled {
		coordinator = &blocklistCoordinator{
			byAccount: make(map[string][]string),
			client:    unifi.New(conf.Unifi),
		}
	}
	// events are used to forward deltas and weekly snapshots to all workers
	// through one ordered channel per worker.
	eventStreams := make([]chan cf.DecisionEvent, 0)
	var eventSeq uint64
	APICountByToken := make(map[string]*uint32)

	for _, account := range conf.CloudflareConfig.Accounts {
		events := make(chan cf.DecisionEvent)
		eventStreams = append(eventStreams, events)

		var tokenCallCount uint32 = 0
		// we want same reference of tokenCallCount per account token
		if _, ok := APICountByToken[account.Token]; !ok {
			APICountByToken[account.Token] = &tokenCallCount
		}

		worker := cf.CloudflareWorker{
			Account:             account,
			APILogger:           APILogger,
			Ctx:                 ctx,
			Events:              events,
			UpdateFrequency:     conf.CloudflareConfig.UpdateFrequency,
			FullResyncFrequency: conf.CloudflareConfig.FullResyncFrequency,
			CFStateByAction:     make(map[string]*cf.CloudflareState),
			TokenCallCount:      APICountByToken[account.Token],
		}
		worker.SetRankingConfig(conf.CloudflareConfig.Ranking)
		if conf.Unifi.Enabled {
			worker.BlocklistListener = coordinator
		}
		if *onlySetup {
			g.Go(func() error {
				var err error
				worker.CFStateByAction = nil
				err = worker.Init()
				if err != nil {
					return err
				}
				return worker.Setup()
			})
		} else if *delete {
			g.Go(func() error {
				var err error
				err = worker.Init()
				if err != nil {
					return err
				}
				if err := worker.DeleteCrowdSecRules(); err != nil {
					return err
				}
				return worker.DeleteExistingIPList()
			})
		} else {
			g.Go(func() error {
				err := worker.Run()
				return err
			})
		}
	}

	if !*onlySetup && !*delete {
		log.Infof("Starting %s %s", name, version.String())
		streamOpts := apiclient.DecisionsStreamOpts{
			Scopes:                 "ip,range,as,country",
			ScenariosNotContaining: strings.Join(conf.ExcludeScenariosContaining, ","),
			ScenariosContaining:    strings.Join(conf.IncludeScenariosContaining, ","),
			Origins:                strings.Join(conf.OnlyIncludeDecisionsFrom, ","),
		}
		csLAPI = &csbouncer.StreamBouncer{
			APIKey:         conf.CrowdSecLAPIKey,
			APIUrl:         conf.CrowdSecLAPIUrl,
			TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
			UserAgent:      fmt.Sprintf("%s/%s", name, version.String()),
			Opts: streamOpts,
			CertPath:           conf.CertPath,
			KeyPath:            conf.KeyPath,
			CAPath:             conf.CAPath,
			InsecureSkipVerify: &conf.CrowdSecInsecureSkipVerify,
		}
		if err := csLAPI.Init(); err != nil {
			return err
		}
		if *testConfig {
			log.Info("config is valid")
			return nil
		}
		g.Go(func() error {
			csLAPI.Run(ctx)
			return fmt.Errorf("crowdsec LAPI stream has stopped")
		})
		g.Go(func() error {
			ticker := time.NewTicker(conf.CloudflareConfig.FullResyncFrequency)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					opts := streamOpts
					opts.Startup = true
					snapshot, resp, err := csLAPI.APIClient.Decisions.GetStream(ctx, opts)
					if resp != nil && resp.Response != nil {
						resp.Response.Body.Close()
					}
					if err != nil {
						log.Errorf("full resync failed: %s", err)
						continue
					}
					seq := atomic.AddUint64(&eventSeq, 1)
					for _, events := range eventStreams {
						stream := events
						go func() { stream <- cf.DecisionEvent{Decisions: snapshot, FullSnapshot: true, Seq: seq} }()
					}
				}
			}
		})
		if conf.Unifi.Enabled {
			g.Go(func() error {
				ticker := time.NewTicker(conf.Unifi.UpdateFrequency)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-ticker.C:
						if err := coordinator.Sync(ctx); err != nil {
							log.Errorf("unifi group sync failed: %s", err)
						}
					}
				}
			})
		}
		g.Go(func() error {
			for {
				// broadcast decision to each worker
				select {
				case decisions := <-csLAPI.Stream:
					seq := atomic.AddUint64(&eventSeq, 1)
					for _, events := range eventStreams {
						stream := events
						go func() { stream <- cf.DecisionEvent{Decisions: decisions, Seq: seq} }()
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
	}

	if conf.PrometheusConfig.Enabled {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Error(http.ListenAndServe(net.JoinHostPort(conf.PrometheusConfig.ListenAddress, conf.PrometheusConfig.ListenPort), nil))
		}()
	}

	apiCallCounterWindow := time.NewTicker(time.Second)
	go func() {
		for {
			<-apiCallCounterWindow.C
			for token := range APICountByToken {
				atomic.SwapUint32(APICountByToken[token], 0)
			}
		}
	}()

	_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}
	if *delete {
		log.Info("deleted all cf config")
	}
	if *onlySetup {
		log.Info("setup complete")
	}
	return nil
}
