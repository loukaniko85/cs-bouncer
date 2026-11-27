package cmd

import (
	"bytes"
	"context"
	"errors"
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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cf"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/rank"
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
	expected  []string
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
	if len(c.expected) > 0 {
		ready = true
		for _, accountID := range c.expected {
			if _, ok := c.byAccount[accountID]; !ok {
				ready = false
				break
			}
		}
	}
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

func HandleSignals(ctx context.Context, cancel context.CancelFunc) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(signalChan)

	select {
	case <-signalChan:
		cancel()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newAPILogger(logDir string, logAPIRequests *bool) (*log.Logger, error) {
	APILogger := log.New()
	if *logAPIRequests {
		APILogger.SetOutput(&lumberjack.Logger{
			Filename:   filepath.Join(logDir, "crowdsec-cloudflare-bouncer-api-calls.log"),
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		})
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
	dump := flag.Bool("dump", false, "print the ranked blocklist and exit")
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
			err := cfg.WriteConfigFile(*configOutputPath, []byte(cfgTokenString))
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
		fmt.Println(string(cfg.RedactSecrets(configBytes)))
		return nil
	}

	conf, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to parse config: %w", err)
	}
	if *testConfig {
		log.Info("config is valid")
		return nil
	}

	if *delete || *onlySetup {
		log.SetOutput(os.Stdout)
	}

	APILogger, err := newAPILogger(conf.Logging.LogDir, logAPIRequests)
	if err != nil {
		return err
	}

	if *dump {
		ctx := context.Background()
		opts := apiclient.DecisionsStreamOpts{
			Startup:                true,
			Scopes:                 "ip,range,as,country",
			ScenariosNotContaining: strings.Join(conf.ExcludeScenariosContaining, ","),
			ScenariosContaining:    strings.Join(conf.IncludeScenariosContaining, ","),
			Origins:                strings.Join(conf.OnlyIncludeDecisionsFrom, ","),
		}
		bouncer := &csbouncer.StreamBouncer{
			APIKey:             conf.CrowdSecLAPIKey,
			APIUrl:             conf.CrowdSecLAPIUrl,
			UserAgent:          fmt.Sprintf("%s/%s", name, version.String()),
			Opts:               opts,
			CertPath:           conf.CertPath,
			KeyPath:            conf.KeyPath,
			CAPath:             conf.CAPath,
			InsecureSkipVerify: &conf.CrowdSecInsecureSkipVerify,
		}
		if err := bouncer.Init(); err != nil {
			return err
		}
		stream, resp, err := bouncer.APIClient.Decisions.GetStream(ctx, opts)
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}
		if err != nil {
			return err
		}
		ranker, err := rank.New(conf.CloudflareConfig.Ranking)
		if err != nil {
			return err
		}
		capacity := 0
		for _, account := range conf.CloudflareConfig.Accounts {
			if account.TotalIPListCapacity != nil && *account.TotalIPListCapacity > capacity {
				capacity = *account.TotalIPListCapacity
			}
		}
		if capacity == 0 {
			capacity = cfg.TotalIPListCapacity
		}
		fmt.Println(strings.Join(cf.RankDecisions(stream.New, ranker, capacity, time.Now()), "\n"))
		return nil
	}

	var csLAPI *csbouncer.StreamBouncer

	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, ctx := errgroup.WithContext(baseCtx)
	var coordinator *blocklistCoordinator
	if conf.Unifi.Enabled {
		accountIDs := make([]string, 0, len(conf.CloudflareConfig.Accounts))
		for _, account := range conf.CloudflareConfig.Accounts {
			accountIDs = append(accountIDs, account.ID)
		}
		coordinator = &blocklistCoordinator{
			byAccount: make(map[string][]string),
			expected:  accountIDs,
			client:    unifi.New(conf.Unifi),
		}
	}
	// events are used to forward deltas and weekly snapshots to all workers
	// through one ordered channel per worker.
	eventStreams := make([]chan cf.DecisionEvent, 0)

	for _, account := range conf.CloudflareConfig.Accounts {
		events := make(chan cf.DecisionEvent)
		eventStreams = append(eventStreams, events)

		worker := cf.CloudflareWorker{
			Account:             account,
			APILogger:           APILogger,
			Ctx:                 ctx,
			Events:              events,
			UpdateFrequency:     conf.CloudflareConfig.UpdateFrequency,
			FullResyncFrequency: conf.CloudflareConfig.FullResyncFrequency,
			CFStateByAction:     make(map[string]*cf.CloudflareState),
			MaxCountryDecisions: conf.CloudflareConfig.MaxCountryDecisions,
			MaxASDecisions:      conf.CloudflareConfig.MaxASDecisions,
		}
		worker.SetRankingConfig(conf.CloudflareConfig.Ranking)
		if conf.StateFile != "" {
			worker.StatePath = cf.StatePath(conf.StateFile, account.ID)
		}
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
		g.Go(func() error {
			return runLAPIPoller(ctx, csLAPI, eventStreams, conf.CloudflareConfig.FullResyncFrequency)
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

	}

	if conf.PrometheusConfig.Enabled {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Error(http.ListenAndServe(net.JoinHostPort(conf.PrometheusConfig.ListenAddress, conf.PrometheusConfig.ListenPort), nil))
		}()
	}

	_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())

	g.Go(func() error {
		return HandleSignals(baseCtx, cancel)
	})

	if err := g.Wait(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
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
