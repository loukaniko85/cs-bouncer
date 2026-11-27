package cf

import (
	"bytes"
	"context"
	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/httplimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
)

var ResponseTime prometheus.Histogram = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "response_time",
	Help:    "response time by cloudflare",
	Buckets: prometheus.LinearBuckets(0, 100, 50),
},
)

var TotalAPICalls prometheus.Counter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cloudflare_api_calls",
	Help: "The total number of API calls to cloudflare made by CrowdSec bouncer",
})

var RankingDroppedTotal prometheus.Counter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "crowdsec_ranking_dropped_total",
	Help: "Decisions dropped because the IP list capacity was exhausted",
})

var ScopedDecisionsDroppedTotal prometheus.Counter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "crowdsec_scoped_decisions_dropped_total",
	Help: "COUNTRY/AS decisions dropped because scoped expression caps were reached",
})

var ListItems prometheus.Gauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "crowdsec_list_items",
	Help: "Number of items currently in the CrowdSec IP list",
})

type cloudflareAPI interface {
	ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error)
	CreateIPList(ctx context.Context, accountID string, name string, desc string, typ string) (cloudflare.IPList, error)
	DeleteIPList(ctx context.Context, accountID string, id string) (cloudflare.IPListDeleteResponse, error)
	ListIPLists(ctx context.Context, accountID string) ([]cloudflare.IPList, error)
	ReplaceIPListItemsAsync(ctx context.Context, accountID string, id string, items []cloudflare.IPListItemCreateRequest) (cloudflare.IPListItemCreateResponse, error)
	GetIPListBulkOperation(ctx context.Context, accountID string, id string) (cloudflare.IPListBulkOperation, error)
	ListIPListItems(ctx context.Context, accountID string, id string) ([]cloudflare.IPListItem, error)
	DeleteIPListItems(ctx context.Context, accountID string, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error)
	GetEntrypointRuleset(ctx context.Context, rc *cloudflare.ResourceContainer, phase string) (cloudflare.Ruleset, error)
	UpdateEntrypointRuleset(ctx context.Context, rc *cloudflare.ResourceContainer, params cloudflare.UpdateEntrypointRulesetParams) (cloudflare.Ruleset, error)
}

func (worker *CloudflareWorker) getAPI() cloudflareAPI {
	TotalAPICalls.Inc()
	return worker.API
}

type InterceptLogger struct {
	Tripper http.RoundTripper
	logger  *log.Logger
}

func (lrt InterceptLogger) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		var buf bytes.Buffer
		tmp := io.TeeReader(req.Body, &buf)
		body, err := io.ReadAll(tmp)
		if err != nil {
			return nil, err
		}
		lrt.logger.Debugf("%s %s", req.URL, string(body))
		req.Body = io.NopCloser(&buf)
	} else {
		lrt.logger.Debugf("%s", req.URL)
	}
	begin := time.Now()
	res, err := lrt.Tripper.RoundTrip(req)
	ResponseTime.Observe(float64(time.Since(begin).Milliseconds()))
	return res, err
}

func NewCloudflareClient(token string, logger *log.Logger) (*cloudflare.API, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &httplimit.RoundTripper{
			Next:  InterceptLogger{Tripper: http.DefaultTransport, logger: logger},
			Rate:  httplimit.DefaultRate,
			Burst: httplimit.DefaultBurst,
		},
	}
	return cloudflare.NewWithAPIToken(token, cloudflare.HTTPClient(httpClient))
}
