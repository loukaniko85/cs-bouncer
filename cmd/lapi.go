package cmd

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cf"
)

type decisionStreamer interface {
	GetStream(context.Context, apiclient.DecisionsStreamOpts) (*models.DecisionsStreamResponse, *apiclient.Response, error)
}

func fetchAndBroadcast(ctx context.Context, streamer decisionStreamer, opts apiclient.DecisionsStreamOpts, streams []chan cf.DecisionEvent, full bool, seq *uint64) error {
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, httpResponse, err := streamer.GetStream(requestCtx, opts)
	if httpResponse != nil && httpResponse.Response != nil {
		httpResponse.Response.Body.Close()
	}
	if err != nil {
		return err
	}
	event := cf.DecisionEvent{
		Decisions:    response,
		FullSnapshot: full,
		Seq:          atomic.AddUint64(seq, 1),
	}
	for _, stream := range streams {
		select {
		case stream <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// runLAPIPoller owns startup, delta and weekly snapshot ordering. It does not
// use StreamBouncer.Run because that helper mixes the startup snapshot into the
// delta channel and performs sends without cancellation.
func runLAPIPoller(ctx context.Context, bouncer *csbouncer.StreamBouncer, streams []chan cf.DecisionEvent, fullResync time.Duration) error {
	streamer := bouncer.APIClient.Decisions
	opts := bouncer.Opts
	var seq uint64

	opts.Startup = true
	if err := fetchAndBroadcast(ctx, streamer, opts, streams, true, &seq); err != nil {
		return fmt.Errorf("initial LAPI snapshot: %w", err)
	}

	ticker := time.NewTicker(bouncer.TickerIntervalDuration)
	defer ticker.Stop()
	nextFullResync := time.Now().Add(fullResync)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			full := !time.Now().Before(nextFullResync)
			opts.Startup = full
			if err := fetchAndBroadcast(ctx, streamer, opts, streams, full, &seq); err != nil {
				log.Errorf("LAPI %s fetch failed: %s", map[bool]string{true: "snapshot", false: "delta"}[full], err)
				continue
			}
			if full {
				nextFullResync = time.Now().Add(fullResync)
			}
		}
	}
}
