package cf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/rank"
)

const CallsPerSecondLimit uint32 = 4
const rulesetPhase = "http_request_firewall_custom"
const ruleDescriptionPrefix = "CrowdSec "

var CloudflareActionByDecisionType = map[string]string{
	"captcha":      "managed_challenge",
	"ban":          "block",
	"js_challenge": "js_challenge",
}

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

var ListItems prometheus.Gauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "crowdsec_list_items",
	Help: "Number of items currently in the CrowdSec IP list",
})

type IPSetItem struct {
	CreatedAt time.Time
}

type IPListState struct {
	IPList *cloudflare.IPList
	IPSet  map[string]IPSetItem `json:"-"`
}

// one rule per state.
type CloudflareState struct {
	Action              string
	AccountID           string
	CurrExpr            string
	IPListState         IPListState
	CountrySet          map[string]struct{}
	AutonomousSystemSet map[string]struct{}
}

func setToExprList(set map[string]struct{}, quotes bool) string {
	items := make([]string, len(set))
	i := 0
	for str := range set {
		if quotes {
			items[i] = fmt.Sprintf(`"%s"`, str)
		} else {
			items[i] = str
		}
		i++
	}
	sort.Strings(items)
	return fmt.Sprintf("{%s}", strings.Join(items, " "))
}

func allZonesHaveAction(zones []cfg.ZoneConfig, action string) bool {
	for _, zone := range zones {
		if _, ok := zone.ActionSet[action]; !ok {
			return false
		}
	}
	return true
}

func (cfState CloudflareState) computeExpression() string {
	var buff []string
	if len(cfState.CountrySet) > 0 {
		buff = append(buff, fmt.Sprintf("(ip.geoip.country in %s)", setToExprList(cfState.CountrySet, true)))
	}
	if len(cfState.AutonomousSystemSet) > 0 {
		buff = append(buff, fmt.Sprintf("(ip.geoip.asnum in %s)", setToExprList(cfState.AutonomousSystemSet, false)))
	}
	if cfState.IPListState.IPList != nil {
		buff = append(buff, fmt.Sprintf("(ip.src in $%s)", cfState.IPListState.IPList.Name))
	}
	return strings.Join(buff, " or ")
}

func (cfState *CloudflareState) UpdateExpr() bool {
	computedExpr := cfState.computeExpression()
	isNew := computedExpr != cfState.CurrExpr
	cfState.CurrExpr = computedExpr
	return isNew
}

// RankedBlocklistListener receives each worker's ranked IPs after trimming.
type RankedBlocklistListener interface {
	Publish(accountID string, ips []string)
}

// DecisionEvent carries a stream update with a monotonic sequence number so a
// delayed weekly snapshot cannot overwrite newer LAPI deltas.
type DecisionEvent struct {
	Decisions    *models.DecisionsStreamResponse
	FullSnapshot bool
	Seq          uint64
}

type CloudflareWorker struct {
	Logger              *log.Entry
	APILogger           *log.Logger
	Account             cfg.AccountConfig
	Zones               []cloudflare.Zone
	CFStateByAction     map[string]*CloudflareState
	IPListState         IPListState
	ActiveDecisions     map[string]map[string]*models.Decision
	Ranker              *rank.Ranker
	BlocklistListener   RankedBlocklistListener
	rankingConfig       cfg.RankingConfig
	Ctx                 context.Context
	Events              chan DecisionEvent
	lastEventSeq        uint64
	UpdateFrequency     time.Duration
	FullResyncFrequency time.Duration
	nextReconcile       time.Time
	API                 cloudflareAPI
	Count               prometheus.Counter
	TokenCallCount      *uint32
}

// this is useful for testing allowing us to mock it.
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

func decisionKey(d *models.Decision) string {
	if d == nil {
		return ""
	}
	value, scenario, typ, origin, duration := "", "", "", "", ""
	if d.Value != nil {
		value = *d.Value
	}
	if d.Scenario != nil {
		scenario = *d.Scenario
	}
	if d.Type != nil {
		typ = *d.Type
	}
	if d.Origin != nil {
		origin = *d.Origin
	}
	if d.Duration != nil {
		duration = *d.Duration
	}
	return strings.Join([]string{value, scenario, typ, origin, duration, d.Until}, "|")
}

func normalizeDecisionValue(value string) string {
	if strings.Count(value, ":") <= 1 {
		if strings.HasSuffix(value, "/32") {
			return value[:len(value)-3]
		}
		return value
	}
	_, address, err := net.ParseCIDR(value)
	if err != nil {
		_, address, _ = net.ParseCIDR(value + "/64")
	}
	if ones, _ := address.Mask.Size(); ones < 64 {
		return address.String()
	}
	address.Mask = net.CIDRMask(64, 128)
	return address.String()
}

func (worker *CloudflareWorker) getAPI() cloudflareAPI {
	atomic.AddUint32(worker.TokenCallCount, 1)
	if *worker.TokenCallCount > CallsPerSecondLimit {
		time.Sleep(time.Second)
	}
	TotalAPICalls.Inc()
	return worker.API
}

func (worker *CloudflareWorker) addDecision(d *models.Decision) {
	if d == nil || d.Value == nil {
		return
	}
	value := normalizeDecisionValue(*d.Value)
	if worker.ActiveDecisions[value] == nil {
		worker.ActiveDecisions[value] = make(map[string]*models.Decision)
	}
	worker.ActiveDecisions[value][decisionKey(d)] = d
}

func (worker *CloudflareWorker) removeDecision(d *models.Decision) {
	if d == nil || d.Value == nil {
		return
	}
	value := normalizeDecisionValue(*d.Value)
	delete(worker.ActiveDecisions[value], decisionKey(d))
	if len(worker.ActiveDecisions[value]) == 0 {
		delete(worker.ActiveDecisions, value)
	}
}

// ApplyStream applies new and deleted decisions from the LAPI stream.
func (worker *CloudflareWorker) ApplyStream(s *models.DecisionsStreamResponse) {
	if s == nil {
		return
	}
	for _, d := range s.New {
		worker.addDecision(d)
	}
	for _, d := range s.Deleted {
		worker.removeDecision(d)
	}
}

// applyEvent applies an event unless an older-numbered event already arrived.
func (worker *CloudflareWorker) applyEvent(e DecisionEvent) {
	if e.Seq != 0 {
		if e.Seq < worker.lastEventSeq {
			worker.Logger.Debugf("ignoring stale decision event %d", e.Seq)
			return
		}
		worker.lastEventSeq = e.Seq
	}
	if e.FullSnapshot {
		worker.ApplyFullSnapshot(e.Decisions)
	} else {
		worker.ApplyStream(e.Decisions)
	}
}

// ApplyFullSnapshot replaces the decision set with a fresh startup snapshot.
func (worker *CloudflareWorker) ApplyFullSnapshot(s *models.DecisionsStreamResponse) {
	worker.ActiveDecisions = make(map[string]map[string]*models.Decision)
	if s == nil {
		return
	}
	for _, d := range s.New {
		worker.addDecision(d)
	}
}

func (worker *CloudflareWorker) importExistingIPLists() error {
	lists, err := worker.getAPI().ListIPLists(worker.Ctx, worker.Account.ID)
	if err != nil {
		return err
	}
	var legacy *cloudflare.IPList
	for i := range lists {
		list := lists[i]
		if list.Name == worker.Account.IPListName {
			worker.Logger.Infof("using existing ip list %s %s", list.Name, list.ID)
			worker.IPListState.IPList = &list
			return nil
		}
		if strings.Contains(list.Description, "IP list by crowdsec") {
			legacy = &list
		}
	}
	// Cloudflare permits only one bulk update every 24h for lists that look
	// CrowdSec-managed. Replace such a list with a neutral one.
	if legacy != nil {
		worker.Logger.Warnf("migrating from CrowdSec-managed list %s to %s", legacy.Name, worker.Account.IPListName)
		if err := worker.DeleteCrowdSecRules(); err != nil {
			return err
		}
		if _, err := worker.getAPI().DeleteIPList(worker.Ctx, worker.Account.ID, legacy.ID); err != nil {
			return err
		}
	}
	return nil
}

func (worker *CloudflareWorker) createMissingIPLists() error {
	if worker.IPListState.IPList == nil {
		list, err := worker.getAPI().CreateIPList(
			worker.Ctx,
			worker.Account.ID,
			worker.Account.IPListName,
			"Managed block list",
			"ip",
		)
		if err != nil {
			return err
		}
		worker.IPListState.IPList = &list
	}
	if worker.IPListState.IPSet == nil {
		worker.IPListState.IPSet = make(map[string]IPSetItem)
	}
	return nil
}

func (worker *CloudflareWorker) cachedListZones() ([]cloudflare.Zone, error) {
	if len(worker.Zones) != 0 {
		return worker.Zones, nil
	}
	zones, err := worker.getAPI().ListZones(worker.Ctx)
	if err != nil {
		return nil, err
	}
	worker.Zones = zones
	return zones, nil
}

func (worker *CloudflareWorker) DeleteExistingIPList() error {
	lists, err := worker.getAPI().ListIPLists(worker.Ctx, worker.Account.ID)
	if err != nil {
		return err
	}
	for _, list := range lists {
		if list.Name == worker.Account.IPListName || strings.Contains(list.Description, "IP list by crowdsec") {
			worker.Logger.Infof("deleting ip list %s", list.Name)
			if _, err := worker.getAPI().DeleteIPList(worker.Ctx, worker.Account.ID, list.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (worker *CloudflareWorker) replaceListItems(set map[string]IPSetItem) error {
	id := worker.IPListState.IPList.ID
	if len(set) == 0 {
		// ReplaceIPListItemsAsync cannot empty a list; add a placeholder then delete it.
		set["10.0.0.1"] = IPSetItem{CreatedAt: time.Now()}
		defer func() {
			items, err := worker.getAPI().ListIPListItems(worker.Ctx, worker.Account.ID, id)
			if err == nil && len(items) > 0 {
				_, err = worker.getAPI().DeleteIPListItems(worker.Ctx, worker.Account.ID, id, cloudflare.IPListItemDeleteRequest{
					Items: []cloudflare.IPListItemDeleteItemRequest{{ID: items[0].ID}},
				})
			}
			if err != nil {
				worker.Logger.Error(err)
			}
			worker.IPListState.IPSet = make(map[string]IPSetItem)
			worker.IPListState.IPList.NumItems = 0
		}()
	}

	req := make([]cloudflare.IPListItemCreateRequest, 0, len(set))
	for ip := range set {
		req = append(req, cloudflare.IPListItemCreateRequest{IP: ip})
	}
	ret, err := worker.getAPI().ReplaceIPListItemsAsync(worker.Ctx, worker.Account.ID, id, req)
	if err != nil {
		return err
	}
	for {
		res, err := worker.getAPI().GetIPListBulkOperation(worker.Ctx, worker.Account.ID, ret.Result.OperationID)
		if err != nil {
			return err
		}
		switch res.Status {
		case "failed":
			return fmt.Errorf("failed during polling got error %s", res.Error)
		case "pending", "running":
			time.Sleep(time.Second)
		case "completed":
			worker.IPListState.IPSet = set
			worker.IPListState.IPList.NumItems = len(set)
			ListItems.Set(float64(len(set)))
			return nil
		default:
			return fmt.Errorf("unexpected status %s while polling", res.Status)
		}
	}
}

func (worker *CloudflareWorker) pruneExpired(now time.Time) {
	for value, decisions := range worker.ActiveDecisions {
		for key, d := range decisions {
			if d.Until == "" {
				continue
			}
			until, err := time.Parse(time.RFC3339, d.Until)
			if err == nil && until.Before(now) {
				delete(decisions, key)
			}
		}
		if len(decisions) == 0 {
			delete(worker.ActiveDecisions, value)
		}
	}
}

func (worker *CloudflareWorker) publishRankedIPs(ranked []*models.Decision) {
	if worker.BlocklistListener == nil {
		return
	}
	ips := make([]string, 0, len(ranked))
	for _, d := range ranked {
		if d.Value != nil {
			ips = append(ips, *d.Value)
		}
	}
	worker.BlocklistListener.Publish(worker.Account.ID, ips)
}

// Reconcile recomputes the desired list contents from active decisions.
func (worker *CloudflareWorker) Reconcile() error {
	now := time.Now()
	worker.pruneExpired(now)

	ipDecisions := make([]*models.Decision, 0)
	for _, decisions := range worker.ActiveDecisions {
		for _, d := range decisions {
			if d.Scope == nil {
				continue
			}
			switch strings.ToUpper(*d.Scope) {
			case "IP", "RANGE":
				ipDecisions = append(ipDecisions, d)
			}
		}
	}

	// Normalize before ranking and before applying the capacity limit, so
	// equivalent values (e.g. 1.2.3.4 and 1.2.3.4/32) cannot waste slots.
	normalized := make([]*models.Decision, 0, len(ipDecisions))
	for _, d := range ipDecisions {
		if d.Value == nil {
			continue
		}
		copyOfDecision := *d
		value := normalizeDecisionValue(*d.Value)
		copyOfDecision.Value = &value
		normalized = append(normalized, &copyOfDecision)
	}
	ranked := worker.Ranker.Rank(normalized, now)
	capacity := cfg.TotalIPListCapacity
	if worker.Account.TotalIPListCapacity != nil {
		capacity = *worker.Account.TotalIPListCapacity
	}
	if len(ranked) > capacity {
		RankingDroppedTotal.Add(float64(len(ranked) - capacity))
		ranked = ranked[:capacity]
	}

	worker.publishRankedIPs(ranked)

	newSet := make(map[string]IPSetItem, len(ranked))
	for _, d := range ranked {
		value := *d.Value
		if old, ok := worker.IPListState.IPSet[value]; ok {
			newSet[value] = old
		} else {
			newSet[value] = IPSetItem{CreatedAt: now}
		}
	}
	if !reflect.DeepEqual(worker.IPListState.IPSet, newSet) {
		if err := worker.replaceListItems(newSet); err != nil {
			return fmt.Errorf("replacing list items: %w", err)
		}
	} else {
		ListItems.Set(float64(len(newSet)))
	}

	worker.refreshScopedSets()
	for _, state := range worker.CFStateByAction {
		state.UpdateExpr()
	}
	if err := worker.UpdateRules(); err != nil {
		return fmt.Errorf("updating rules: %w", err)
	}
	return nil
}

func (worker *CloudflareWorker) refreshScopedSets() {
	for _, state := range worker.CFStateByAction {
		state.CountrySet = make(map[string]struct{})
		state.AutonomousSystemSet = make(map[string]struct{})
	}
	for _, decisions := range worker.ActiveDecisions {
		for _, d := range decisions {
			if d.Scope == nil || d.Value == nil || d.Type == nil {
				continue
			}
			action := CloudflareActionByDecisionType[*d.Type]
			if action == "" || !allZonesHaveAction(worker.Account.ZoneConfigs, action) {
				action = worker.Account.DefaultAction
			}
			state := worker.CFStateByAction[action]
			if state == nil {
				continue
			}
			switch strings.ToUpper(*d.Scope) {
			case "COUNTRY":
				state.CountrySet[*d.Value] = struct{}{}
			case "AS":
				state.AutonomousSystemSet[*d.Value] = struct{}{}
			}
		}
	}
}

func rulesEqual(a, b []cloudflare.RulesetRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Description != b[i].Description || a[i].Action != b[i].Action || a[i].Expression != b[i].Expression {
			return false
		}
	}
	return true
}

// UpdateRules keeps one rule per configured action in each zone's
// http_request_firewall_custom entry-point ruleset, preserving user rules.
func (worker *CloudflareWorker) UpdateRules() error {
	for _, zone := range worker.Account.ZoneConfigs {
		rc := cloudflare.ZoneIdentifier(zone.ID)
		current, err := worker.getAPI().GetEntrypointRuleset(worker.Ctx, rc, rulesetPhase)
		if err != nil {
			return fmt.Errorf("zone %s: reading entrypoint ruleset: %w", zone.ID, err)
		}
		desired := make([]cloudflare.RulesetRule, 0, len(current.Rules)+len(zone.Actions))
		for _, rule := range current.Rules {
			if !strings.HasPrefix(rule.Description, ruleDescriptionPrefix) {
				desired = append(desired, rule)
			}
		}
		for _, action := range zone.Actions {
			state := worker.CFStateByAction[action]
			if state == nil {
				continue
			}
			expression := state.CurrExpr
			if expression == "" {
				expression = state.computeExpression()
			}
			desired = append(desired, cloudflare.RulesetRule{
				Action:      action,
				Expression:  expression,
				Description: ruleDescriptionPrefix + action + " rule",
			})
		}
		if rulesEqual(current.Rules, desired) {
			continue
		}
		worker.Logger.WithField("zone_id", zone.ID).Infof("updating %d rulesets rules", len(desired))
		if _, err := worker.getAPI().UpdateEntrypointRuleset(worker.Ctx, rc, cloudflare.UpdateEntrypointRulesetParams{
			Phase: rulesetPhase,
			Rules: desired,
		}); err != nil {
			return fmt.Errorf("zone %s: writing entrypoint ruleset: %w", zone.ID, err)
		}
	}
	return nil
}

func (worker *CloudflareWorker) Init() error {
	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	if worker.API == nil {
		api, err := NewCloudflareClient(worker.Account.Token, worker.APILogger)
		if err != nil {
			return err
		}
		worker.API = api
	}
	if worker.Ranker == nil {
		ranker, err := rank.New(worker.rankingConfig)
		if err != nil {
			return err
		}
		worker.Ranker = ranker
	}
	if worker.ActiveDecisions == nil {
		worker.ActiveDecisions = make(map[string]map[string]*models.Decision)
	}
	if worker.IPListState.IPSet == nil {
		worker.IPListState.IPSet = make(map[string]IPSetItem)
	}
	worker.CFStateByAction = make(map[string]*CloudflareState)
	zones, err := worker.cachedListZones()
	if err != nil {
		return err
	}
	zoneByID := make(map[string]cloudflare.Zone, len(zones))
	for _, zone := range zones {
		zoneByID[zone.ID] = zone
	}
	for _, z := range worker.Account.ZoneConfigs {
		if _, ok := zoneByID[z.ID]; !ok {
			return fmt.Errorf("account %s doesn't have access to zone %s", worker.Account.ID, z.ID)
		}
		if !zoneByID[z.ID].Plan.IsSubscribed && len(z.Actions) > 1 {
			return fmt.Errorf("zone %s 's plan doesn't support multiple actions", z.ID)
		}
		for _, action := range z.Actions {
			if worker.CFStateByAction[action] == nil {
				worker.CFStateByAction[action] = &CloudflareState{
					Action:              action,
					AccountID:           worker.Account.ID,
					CountrySet:          make(map[string]struct{}),
					AutonomousSystemSet: make(map[string]struct{}),
				}
			}
		}
	}
	return nil
}

// SetRankingConfig attaches the ranking configuration to the worker.
func (worker *CloudflareWorker) SetRankingConfig(config cfg.RankingConfig) {
	worker.rankingConfig = config
}

func (worker *CloudflareWorker) SetUpCloudflareResources() error {
	if err := worker.importExistingIPLists(); err != nil {
		return err
	}
	if err := worker.createMissingIPLists(); err != nil {
		return err
	}
	for _, state := range worker.CFStateByAction {
		state.IPListState = worker.IPListState
		state.UpdateExpr()
	}
	return nil
}

// Setup creates the list and its rules (used by the -s CLI flag).
func (worker *CloudflareWorker) Setup() error {
	if err := worker.SetUpCloudflareResources(); err != nil {
		return err
	}
	return worker.UpdateRules()
}

// DeleteCrowdSecRules removes our rules from every zone before the IP list is deleted.
func (worker *CloudflareWorker) DeleteCrowdSecRules() error {
	for _, zone := range worker.Account.ZoneConfigs {
		rc := cloudflare.ZoneIdentifier(zone.ID)
		current, err := worker.getAPI().GetEntrypointRuleset(worker.Ctx, rc, rulesetPhase)
		if err != nil {
			return fmt.Errorf("zone %s: reading entrypoint ruleset: %w", zone.ID, err)
		}
		kept := make([]cloudflare.RulesetRule, 0, len(current.Rules))
		for _, rule := range current.Rules {
			if !strings.HasPrefix(rule.Description, ruleDescriptionPrefix) {
				kept = append(kept, rule)
			}
		}
		if len(kept) == len(current.Rules) {
			continue
		}
		worker.Logger.WithField("zone_id", zone.ID).Info("removing CrowdSec rules")
		if _, err := worker.getAPI().UpdateEntrypointRuleset(worker.Ctx, rc, cloudflare.UpdateEntrypointRulesetParams{
			Phase: rulesetPhase,
			Rules: kept,
		}); err != nil {
			return err
		}
	}
	return nil
}

// reconcileTick logs transient failures so the daemon retries on the next tick.
func (worker *CloudflareWorker) reconcileTick() error {
	if time.Now().Before(worker.nextReconcile) {
		return nil
	}
	err := worker.Reconcile()
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "10040") || strings.Contains(message, "24 hours") {
		worker.nextReconcile = time.Now().Add(24 * time.Hour)
		worker.Logger.Warnf("Cloudflare allows one bulk list update per 24h for CrowdSec-managed lists; pausing until %s. Rename the list to avoid this limit: %s", worker.nextReconcile.Format(time.RFC3339), err)
		return nil
	}
	if strings.Contains(message, "rate limit") || strings.Contains(message, "too many requests") || strings.Contains(message, "429") {
		worker.nextReconcile = time.Now().Add(5 * time.Minute)
		worker.Logger.Warnf("cloudflare rate limited, pausing reconciliation until %s: %s", worker.nextReconcile.Format(time.RFC3339), err)
		return nil
	}
	worker.Logger.Errorf("reconcile failed, retrying next tick: %s", err)
	return nil
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
		Transport: InterceptLogger{Tripper: http.DefaultTransport, logger: logger},
	}
	return cloudflare.NewWithAPIToken(token, cloudflare.HTTPClient(httpClient))
}

func (worker *CloudflareWorker) Run() error {
	if err := worker.Init(); err != nil {
		return err
	}
	if err := worker.SetUpCloudflareResources(); err != nil {
		return err
	}
	ticker := time.NewTicker(worker.UpdateFrequency)
	defer ticker.Stop()
	for {
		select {
		case <-worker.Ctx.Done():
			return worker.Ctx.Err()
		case <-ticker.C:
			worker.reconcileTick()
		case event := <-worker.Events:
			worker.applyEvent(event)
		}
	}
}
