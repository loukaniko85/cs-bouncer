package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cf"
)

type fakeDecisionStreamer struct {
	startup  bool
	response *models.DecisionsStreamResponse
	err      error
}

func (f *fakeDecisionStreamer) GetStream(ctx context.Context, opts apiclient.DecisionsStreamOpts) (*models.DecisionsStreamResponse, *apiclient.Response, error) {
	f.startup = opts.Startup
	return f.response, nil, f.err
}

func TestFetchAndBroadcastMarksStartupSnapshot(t *testing.T) {
	streamer := &fakeDecisionStreamer{response: &models.DecisionsStreamResponse{}}
	events := make(chan cf.DecisionEvent, 1)
	err := fetchAndBroadcast(context.Background(), streamer, apiclient.DecisionsStreamOpts{Startup: true}, []chan cf.DecisionEvent{events}, true, new(uint64))
	require.NoError(t, err)
	require.True(t, streamer.startup)
	event := <-events
	require.True(t, event.FullSnapshot)
}

func TestFetchAndBroadcastRespectsCancellation(t *testing.T) {
	streamer := &fakeDecisionStreamer{response: &models.DecisionsStreamResponse{}}
	events := make(chan cf.DecisionEvent) // no receiver
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := fetchAndBroadcast(ctx, streamer, apiclient.DecisionsStreamOpts{}, []chan cf.DecisionEvent{events}, false, new(uint64))
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestFetchAndBroadcastReturnsStreamError(t *testing.T) {
	streamer := &fakeDecisionStreamer{err: errors.New("lapi down")}
	err := fetchAndBroadcast(context.Background(), streamer, apiclient.DecisionsStreamOpts{}, nil, false, new(uint64))
	require.ErrorContains(t, err, "lapi down")
}
