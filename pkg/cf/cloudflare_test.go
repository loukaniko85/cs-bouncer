package cf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/rank"
)

var mockAPICallCounter uint32

type mockCloudflareAPI struct {
	IPLists               []cloudflare.IPList
	IPListItems           map[string][]cloudflare.IPListItem
	ZoneList              []cloudflare.Zone
	EntrypointRuleset     cloudflare.Ruleset
	CreateIPListCalls     int
	ReplaceCalls          int
	UpdateEntrypointCalls int
	GetEntrypointCalls    int
	EntrypointErr         error
	DeletedListIDs        []string
}

func (m *mockCloudflareAPI) ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error) {
	return m.ZoneList, nil
}

func (m *mockCloudflareAPI) CreateIPList(ctx context.Context, accountID, name, desc, typ string) (cloudflare.IPList, error) {
	m.CreateIPListCalls++
	list := cloudflare.IPList{ID: strconv.Itoa(len(m.IPLists) + 1), Name: name, Description: desc}
	m.IPLists = append(m.IPLists, list)
	return list, nil
}

func (m *mockCloudflareAPI) DeleteIPList(ctx context.Context, accountID, id string) (cloudflare.IPListDeleteResponse, error) {
	m.DeletedListIDs = append(m.DeletedListIDs, id)
	for i, l := range m.IPLists {
		if l.ID == id {
			m.IPLists = append(m.IPLists[:i], m.IPLists[i+1:]...)
			break
		}
	}
	return cloudflare.IPListDeleteResponse{}, nil
}

func (m *mockCloudflareAPI) ListIPLists(ctx context.Context, accountID string) ([]cloudflare.IPList, error) {
	return m.IPLists, nil
}

func (m *mockCloudflareAPI) ReplaceIPListItemsAsync(ctx context.Context, accountID, id string, items []cloudflare.IPListItemCreateRequest) (cloudflare.IPListItemCreateResponse, error) {
	m.ReplaceCalls++
	m.IPListItems[id] = make([]cloudflare.IPListItem, len(items))
	for i, item := range items {
		m.IPListItems[id][i] = cloudflare.IPListItem{IP: item.IP}
	}
	return cloudflare.IPListItemCreateResponse{}, nil
}

func (m *mockCloudflareAPI) GetIPListBulkOperation(ctx context.Context, accountID, id string) (cloudflare.IPListBulkOperation, error) {
	return cloudflare.IPListBulkOperation{Status: "completed"}, nil
}

func (m *mockCloudflareAPI) ListIPListItems(ctx context.Context, accountID, id string) ([]cloudflare.IPListItem, error) {
	return m.IPListItems[id], nil
}

func (m *mockCloudflareAPI) DeleteIPListItems(ctx context.Context, accountID, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error) {
	return m.IPListItems[id], nil
}

func (m *mockCloudflareAPI) GetEntrypointRuleset(ctx context.Context, rc *cloudflare.ResourceContainer, phase string) (cloudflare.Ruleset, error) {
	m.GetEntrypointCalls++
	if m.EntrypointErr != nil {
		return cloudflare.Ruleset{}, m.EntrypointErr
	}
	return m.EntrypointRuleset, nil
}

func (m *mockCloudflareAPI) UpdateEntrypointRuleset(ctx context.Context, rc *cloudflare.ResourceContainer, params cloudflare.UpdateEntrypointRulesetParams) (cloudflare.Ruleset, error) {
	m.UpdateEntrypointCalls++
	m.EntrypointRuleset = cloudflare.Ruleset{Phase: params.Phase, Rules: params.Rules}
	return m.EntrypointRuleset, nil
}

var testRankingCfg = cfg.RankingConfig{
	Patterns: []cfg.RankingPattern{
		{Name: "zero_day", Pattern: `(?i)(0day|cve-2026)`, Score: 100},
		{Name: "scanning", Pattern: `(?i)scan`, Score: 10},
	},
	DefaultScore:         20,
	TypeScores:           map[string]int{"ban": 20, "captcha": 5},
	DurationBonusPerHour: 1,
	DurationBonusMax:     20,
	OriginScores:         map[string]int{"crowdsec": 10},
}

func newTestWorker(t *testing.T, api cloudflareAPI, account cfg.AccountConfig) *CloudflareWorker {
	t.Helper()
	r, err := rank.New(testRankingCfg)
	require.NoError(t, err)
	return &CloudflareWorker{
		API:     api,
		Account: account,
		Logger:  log.WithField("account_id", account.ID),
		Count:   prometheus.NewCounter(prometheus.CounterOpts{}),

		Ctx:             context.Background(),
		IPListState:     IPListState{IPSet: make(map[string]IPSetItem)},
		ActiveDecisions: make(map[string]map[string]*models.Decision),
		CFStateByAction: make(map[string]*CloudflareState),
		Ranker:          r,
	}
}

func testAccount() cfg.AccountConfig {
	capacity := 10000
	return cfg.AccountConfig{
		ID:                  "dummyID",
		ZoneConfigs:         []cfg.ZoneConfig{{ID: "zone1", Actions: []string{"block"}, ActionSet: map[string]struct{}{"block": {}}}},
		IPListPrefix:        "crowdsec",
		IPListName:          "crowdsec_block",
		DefaultAction:       "block",
		TotalIPListCapacity: &capacity,
	}
}

func newDecision(scenario, typ, value, scope string, until time.Time) *models.Decision {
	return &models.Decision{
		Scenario:  ptr.Of(scenario),
		Type:      ptr.Of(typ),
		Value:     ptr.Of(value),
		Scope:     ptr.Of(scope),
		Origin:    ptr.Of("crowdsec"),
		Duration:  ptr.Of("4h"),
		Until:     until.Format(time.RFC3339),
		Simulated: ptr.Of(false),
	}
}

func TestNoLegacyFirewallAPIInInterface(t *testing.T) {
	typ := reflect.TypeOf((*cloudflareAPI)(nil)).Elem()
	for _, name := range []string{
		"Filters", "FirewallRules", "CreateFirewallRules", "DeleteFirewallRules", "UpdateFilters", "DeleteFilters",
	} {
		_, ok := typ.MethodByName(name)
		require.False(t, ok, "legacy method %s is still in cloudflareAPI", name)
	}
	for _, name := range []string{"GetEntrypointRuleset", "UpdateEntrypointRuleset"} {
		_, ok := typ.MethodByName(name)
		require.True(t, ok, "ruleset method %s is missing from cloudflareAPI", name)
	}
}

func TestImportExistingSingleList(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "crowdsec_block", Description: "block IP list by crowdsec"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	require.Equal(t, 0, api.CreateIPListCalls)
	require.Equal(t, "crowdsec_block", w.IPListState.IPList.Name)
}

func TestExistingListHydratedAndClearedByEmptySnapshot(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "wafblocklist"}},
		IPListItems: map[string][]cloudflare.IPListItem{"11": {{IP: "1.1.1.1"}}},
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	account := testAccount()
	account.IPListName = "wafblocklist"
	w := newTestWorker(t, api, account)
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	require.Contains(t, w.IPListState.IPSet, "1.1.1.1")
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{})
	require.NoError(t, w.Reconcile())
	require.Empty(t, api.IPListItems["11"])
	require.NotContains(t, api.IPListItems["11"], cloudflare.IPListItem{IP: "10.0.0.1"})
}

func TestEffectiveCapacityAccountsForOtherLists(t *testing.T) {
	capacity := 2
	account := testAccount()
	account.IPListName = "wafblocklist"
	account.TotalIPListCapacity = &capacity
	api := &mockCloudflareAPI{
		IPLists: []cloudflare.IPList{
			{ID: "11", Name: "wafblocklist"},
			{ID: "12", Name: "other", Kind: "ip", NumItems: 1},
		},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, account)
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	require.Equal(t, 1, w.EffectiveCapacity)
	until := time.Now().Add(time.Hour)
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: []*models.Decision{
		newDecision("http-scan", "ban", "1.1.1.1", "ip", until),
		newDecision("http-scan", "ban", "2.2.2.2", "ip", until),
		newDecision("http-scan", "ban", "3.3.3.3", "ip", until),
	}})
	require.NoError(t, w.Reconcile())
	require.Len(t, api.IPListItems["11"], 1)
}

func TestLegacyListMismatchFailsWithoutDeletion(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "crowdsec_block", Description: "block IP list by crowdsec"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	account := testAccount()
	account.IPListName = "wafblocklist"
	w := newTestWorker(t, api, account)
	require.NoError(t, w.Init())
	err := w.SetUpCloudflareResources()
	require.ErrorContains(t, err, "manual migration")
	require.Empty(t, api.DeletedListIDs)
}

func TestScopedDecisionsValidatedAndCapped(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "wafblocklist"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	w.MaxCountryDecisions = 1
	w.MaxASDecisions = 1
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	until := time.Now().Add(time.Hour)
	w.ActiveDecisions["US"] = map[string]*models.Decision{"us": newDecision("ssh-bf", "ban", "US", "country", until)}
	w.ActiveDecisions["GB"] = map[string]*models.Decision{"gb": newDecision("http-scan", "ban", "GB", "country", until)}
	w.ActiveDecisions["1234"] = map[string]*models.Decision{"as": newDecision("ssh-bf", "ban", "1234", "as", until)}
	w.ActiveDecisions["bad"] = map[string]*models.Decision{"bad": newDecision("ssh-bf", "ban", "not-an-asn", "as", until)}
	require.NoError(t, w.Reconcile())
	require.Equal(t, map[string]struct{}{"US": {}}, w.CFStateByAction["block"].CountrySet)
	require.Equal(t, map[string]struct{}{"1234": {}}, w.CFStateByAction["block"].AutonomousSystemSet)
}

func TestReconcileCapsAtCapacity(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())

	until := time.Now().Add(4 * time.Hour)
	decisions := make([]*models.Decision, 0, 10005)
	for i := 0; i < 5; i++ {
		decisions = append(decisions, newDecision("0day-exploit", "ban", fmt.Sprintf("10.0.0.%d", i), "ip", until))
	}
	for i := 0; i < 10000; i++ {
		decisions = append(decisions, newDecision("http-scan", "ban", fmt.Sprintf("192.0.%d.%d", i/256, i%256), "ip", until))
	}
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: decisions})
	require.NoError(t, w.Reconcile())

	require.Len(t, api.IPListItems["11"], 10000)
	for i := 0; i < 5; i++ {
		require.Contains(t, api.IPListItems["11"], cloudflare.IPListItem{IP: fmt.Sprintf("10.0.0.%d", i)})
	}
}

func TestApplyStreamDeltaExpiry(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	until := time.Now().Add(4 * time.Hour)
	ban := newDecision("ssh-bf", "ban", "1.2.3.4", "ip", until)
	captcha := newDecision("0day-exploit", "captcha", "1.2.3.4", "ip", until)
	w.ApplyStream(&models.DecisionsStreamResponse{New: []*models.Decision{ban, captcha}})
	require.Len(t, w.ActiveDecisions["1.2.3.4"], 2)

	w.ApplyStream(&models.DecisionsStreamResponse{Deleted: []*models.Decision{captcha}})
	require.Len(t, w.ActiveDecisions["1.2.3.4"], 1)

	w.ApplyStream(&models.DecisionsStreamResponse{Deleted: []*models.Decision{ban}})
	require.NotContains(t, w.ActiveDecisions, "1.2.3.4")
}

func TestApplyFullSnapshot(t *testing.T) {
	api := &mockCloudflareAPI{IPListItems: make(map[string][]cloudflare.IPListItem)}
	w := newTestWorker(t, api, testAccount())
	until := time.Now().Add(4 * time.Hour)
	w.ApplyStream(&models.DecisionsStreamResponse{New: []*models.Decision{newDecision("scan", "ban", "9.9.9.9", "ip", until)}})
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: []*models.Decision{
		newDecision("scan", "ban", "1.1.1.1", "ip", until),
		newDecision("scan", "ban", "2.2.2.2", "ip", until),
	}})
	require.Len(t, w.ActiveDecisions, 2)
	require.Contains(t, w.ActiveDecisions, "1.1.1.1")
	require.Contains(t, w.ActiveDecisions, "2.2.2.2")
	require.NotContains(t, w.ActiveDecisions, "9.9.9.9")
}

func TestUpdateEntrypointRulesetPreservesUserRules(t *testing.T) {
	userRule := cloudflare.RulesetRule{
		Description: "my rule",
		Action:      "log",
		Expression:  `cf.zone.name eq "example.com"`,
	}
	api := &mockCloudflareAPI{
		IPListItems: make(map[string][]cloudflare.IPListItem),
		EntrypointRuleset: cloudflare.Ruleset{
			Phase: rulesetPhase,
			Rules: []cloudflare.RulesetRule{
				userRule,
				{Description: "CrowdSec block rule", Action: "block", Expression: "old expression"},
			},
		},
	}
	w := newTestWorker(t, api, testAccount())
	w.CFStateByAction["block"] = &CloudflareState{
		Action:   "block",
		CurrExpr: "(ip.src in $crowdsec_block)",
	}

	require.NoError(t, w.UpdateRules())
	require.Equal(t, 1, api.UpdateEntrypointCalls)
	rules := api.EntrypointRuleset.Rules
	require.Len(t, rules, 2)
	require.Equal(t, userRule, rules[0])
	require.Equal(t, "CrowdSec block rule", rules[1].Description)
	require.Equal(t, "(ip.src in $crowdsec_block)", rules[1].Expression)
	require.Equal(t, "block", rules[1].Action)

	require.NoError(t, w.UpdateRules())
	require.Equal(t, 1, api.UpdateEntrypointCalls, "no-op tick must not write")
}

func TestUpdateRulesUsesRulesetsAPI(t *testing.T) {
	api := &mockCloudflareAPI{IPListItems: make(map[string][]cloudflare.IPListItem)}
	w := newTestWorker(t, api, testAccount())
	w.CFStateByAction["block"] = &CloudflareState{Action: "block", CurrExpr: "(ip.src in $crowdsec_block)"}
	require.NoError(t, w.UpdateRules())
	require.Equal(t, 1, api.UpdateEntrypointCalls)
}

type recordingListener struct {
	accounts []string
	ips      [][]string
}

func (r *recordingListener) Publish(account string, ips []string) {
	r.accounts = append(r.accounts, account)
	r.ips = append(r.ips, ips)
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	active := map[string]map[string]*models.Decision{
		"1.2.3.4": {"ban|ssh-bf|1.2.3.4": newDecision("ssh-bf", "ban", "1.2.3.4", "ip", time.Now().Add(time.Hour))},
	}
	require.NoError(t, SaveState(path, active))
	loaded, err := LoadState(path)
	require.NoError(t, err)
	require.Equal(t, *active["1.2.3.4"]["ban|ssh-bf|1.2.3.4"], *loaded["1.2.3.4"]["ban|ssh-bf|1.2.3.4"])
}

func TestLoadStateDropsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	active := map[string]map[string]*models.Decision{
		"1.2.3.4": {"old": newDecision("ssh-bf", "ban", "1.2.3.4", "ip", time.Now().Add(-time.Hour))},
	}
	require.NoError(t, SaveState(path, active))
	loaded, err := LoadState(path)
	require.NoError(t, err)
	require.Empty(t, loaded)
}

func TestStateFilePerAccount(t *testing.T) {
	template := "/var/lib/cs/state_{account}.json"
	require.Equal(t, "/var/lib/cs/state_a.json", statePath(template, "a"))
	require.Equal(t, "/var/lib/cs/state_b.json", statePath(template, "b"))
}

func TestNormalizeDecisionValueRejectsMalformed(t *testing.T) {
	_, err := normalizeDecisionValue("not:an:ip")
	require.Error(t, err)
}

func TestAddDecisionSkipsMalformedAndSimulated(t *testing.T) {
	api := &mockCloudflareAPI{IPListItems: make(map[string][]cloudflare.IPListItem)}
	w := newTestWorker(t, api, testAccount())
	until := time.Now().Add(time.Hour)
	simulated := newDecision("ssh-bf", "ban", "1.1.1.1", "ip", until)
	simulated.Simulated = ptr.Of(true)
	w.ApplyStream(&models.DecisionsStreamResponse{New: []*models.Decision{
		newDecision("ssh-bf", "ban", "bad:value", "ip", until),
		simulated,
	}})
	require.Empty(t, w.ActiveDecisions)
}

func TestLoadStateSkipsNullDecisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"1.2.3.4":{"bad":null}}`), 0600))
	loaded, err := LoadState(path)
	require.NoError(t, err)
	require.Empty(t, loaded)
}

func TestSimulatedScopedDecisionsNotEnforced(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "wafblocklist"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	until := time.Now().Add(time.Hour)
	country := newDecision("ssh-bf", "ban", "US", "country", until)
	country.Simulated = ptr.Of(true)
	asn := newDecision("ssh-bf", "ban", "1234", "as", until)
	asn.Simulated = ptr.Of(true)
	w.ActiveDecisions["US"] = map[string]*models.Decision{"country": country}
	w.ActiveDecisions["1234"] = map[string]*models.Decision{"as": asn}
	require.NoError(t, w.Reconcile())
	require.Empty(t, w.CFStateByAction["block"].CountrySet)
	require.Empty(t, w.CFStateByAction["block"].AutonomousSystemSet)
}

func TestRankDecisionsMatchesReconcile(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "wafblocklist"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	until := time.Now().Add(4 * time.Hour)
	simulated := newDecision("0day-exploit", "ban", "7.7.7.7", "ip", until)
	simulated.Simulated = ptr.Of(true)
	decisions := []*models.Decision{
		newDecision("0day-exploit", "ban", "1.1.1.1", "ip", until),
		newDecision("http-scan", "ban", "2.2.2.2/32", "ip", until),
		newDecision("http-scan", "ban", "2001:db8::/64", "ip", until),
		newDecision("ssh-bf", "ban", "US", "country", until),
		simulated,
	}
	got := RankDecisions(decisions, w.Ranker, 10000, time.Now())
	require.Equal(t, []string{"1.1.1.1", "2.2.2.2", "2001:db8::/64"}, got)

	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: decisions})
	require.NoError(t, w.Reconcile())
	keys := make([]string, 0, len(w.IPListState.IPSet))
	for key := range w.IPListState.IPSet {
		keys = append(keys, key)
	}
	require.ElementsMatch(t, got, keys)
}

func TestGetAPIIsNonBlocking(t *testing.T) {
	api := &mockCloudflareAPI{IPListItems: make(map[string][]cloudflare.IPListItem)}
	w := newTestWorker(t, api, testAccount())
	start := time.Now()
	for i := 0; i < 10; i++ {
		require.NotNil(t, w.getAPI())
	}
	require.Less(t, time.Since(start), time.Second)
}

func TestReconcilePublishesRankedIPs(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "wafblocklist"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	listener := &recordingListener{}
	w := newTestWorker(t, api, testAccount())
	w.BlocklistListener = listener
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: []*models.Decision{
		newDecision("0day-exploit", "ban", "1.1.1.1", "ip", time.Now().Add(4*time.Hour)),
		newDecision("http-scan", "ban", "2.2.2.2", "ip", time.Now().Add(4*time.Hour)),
	}})
	require.NoError(t, w.Reconcile())
	require.Equal(t, []string{"dummyID"}, listener.accounts)
	require.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, listener.ips[0])
}

func TestReconcilePublishesBeforeCloudflareError(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:       []cloudflare.IPList{{ID: "11", Name: "wafblocklist"}},
		IPListItems:   make(map[string][]cloudflare.IPListItem),
		ZoneList:      []cloudflare.Zone{{ID: "zone1"}},
		EntrypointErr: errors.New("cloudflare down"),
	}
	listener := &recordingListener{}
	w := newTestWorker(t, api, testAccount())
	w.BlocklistListener = listener
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: []*models.Decision{
		newDecision("0day-exploit", "ban", "1.1.1.1", "ip", time.Now().Add(4*time.Hour)),
	}})
	require.Error(t, w.Reconcile())
	require.Equal(t, []string{"1.1.1.1"}, listener.ips[0])
}

func TestReconcileTickSwallowsErrors(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:       []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems:   make(map[string][]cloudflare.IPListItem),
		ZoneList:      []cloudflare.Zone{{ID: "zone1"}},
		EntrypointErr: errors.New("cloudflare 5xx"),
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	require.NoError(t, w.reconcileTick(), "a transient API error must not stop the daemon")
}

func TestReconcileErrorNamesStage(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:       []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems:   make(map[string][]cloudflare.IPListItem),
		ZoneList:      []cloudflare.Zone{{ID: "zone1"}},
		EntrypointErr: errors.New("rate limited"),
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	err := w.Reconcile()
	require.ErrorContains(t, err, "updating rules")
	require.ErrorContains(t, err, "reading entrypoint ruleset")
}

func TestReconcileRateLimitCooldown(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:       []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems:   make(map[string][]cloudflare.IPListItem),
		ZoneList:      []cloudflare.Zone{{ID: "zone1"}},
		EntrypointErr: errors.New("exceeded available rate limit retries"),
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	require.NoError(t, w.reconcileTick())
	require.NoError(t, w.reconcileTick())
	require.Equal(t, 1, api.GetEntrypointCalls, "rate-limited ticks must back off")
}

func TestReconcileNormalizesBeforeCapacity(t *testing.T) {
	capacity := 2
	account := testAccount()
	account.TotalIPListCapacity = &capacity
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, account)
	require.NoError(t, w.Init())
	require.NoError(t, w.SetUpCloudflareResources())
	until := time.Now().Add(4 * time.Hour)
	w.ApplyFullSnapshot(&models.DecisionsStreamResponse{New: []*models.Decision{
		newDecision("http-scan", "ban", "1.2.3.4", "ip", until),
		newDecision("http-scan", "ban", "1.2.3.4/32", "ip", until),
		newDecision("http-scan", "ban", "5.6.7.8", "ip", until),
		newDecision("http-scan", "ban", "9.9.9.9", "ip", until),
	}})
	require.NoError(t, w.Reconcile())
	require.Len(t, api.IPListItems["11"], 2, "equivalent IPs must not consume two slots")
	require.NotContains(t, w.IPListState.IPSet, "1.2.3.4/32")
}

func TestSetupCreatesRules(t *testing.T) {
	api := &mockCloudflareAPI{
		IPLists:     []cloudflare.IPList{{ID: "11", Name: "crowdsec_block"}},
		IPListItems: make(map[string][]cloudflare.IPListItem),
		ZoneList:    []cloudflare.Zone{{ID: "zone1"}},
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.Init())
	require.NoError(t, w.Setup())
	require.Equal(t, 1, api.UpdateEntrypointCalls)
	require.Len(t, api.EntrypointRuleset.Rules, 1)
}

func TestDeleteCrowdSecRules(t *testing.T) {
	userRule := cloudflare.RulesetRule{Description: "my rule", Action: "log", Expression: "true"}
	api := &mockCloudflareAPI{
		IPListItems: make(map[string][]cloudflare.IPListItem),
		EntrypointRuleset: cloudflare.Ruleset{
			Phase: rulesetPhase,
			Rules: []cloudflare.RulesetRule{userRule, {Description: "CrowdSec block rule", Action: "block", Expression: "old"}},
		},
	}
	w := newTestWorker(t, api, testAccount())
	require.NoError(t, w.DeleteCrowdSecRules())
	require.Equal(t, 1, api.UpdateEntrypointCalls)
	require.Equal(t, []cloudflare.RulesetRule{userRule}, api.EntrypointRuleset.Rules)
}

func TestStaleSnapshotIgnored(t *testing.T) {
	api := &mockCloudflareAPI{IPListItems: make(map[string][]cloudflare.IPListItem)}
	w := newTestWorker(t, api, testAccount())
	until := time.Now().Add(4 * time.Hour)
	w.applyEvent(DecisionEvent{Seq: 10, FullSnapshot: true, Decisions: &models.DecisionsStreamResponse{
		New: []*models.Decision{newDecision("scan", "ban", "1.1.1.1", "ip", until)},
	}})
	w.applyEvent(DecisionEvent{Seq: 9, FullSnapshot: true, Decisions: &models.DecisionsStreamResponse{
		New: []*models.Decision{newDecision("scan", "ban", "2.2.2.2", "ip", until)},
	}})
	require.Contains(t, w.ActiveDecisions, "1.1.1.1")
	require.NotContains(t, w.ActiveDecisions, "2.2.2.2")

	w.applyEvent(DecisionEvent{Seq: 11, Decisions: &models.DecisionsStreamResponse{
		New: []*models.Decision{newDecision("scan", "ban", "3.3.3.3", "ip", until)},
	}})
	require.Contains(t, w.ActiveDecisions, "3.3.3.3")
}

func Test_setToExprList(t *testing.T) {
	require.Equal(t, `{1.2.3.4 6.7.8.9}`, setToExprList(map[string]struct{}{"1.2.3.4": {}, "6.7.8.9": {}}, false))
	require.Equal(t, `{"UK" "US"}`, setToExprList(map[string]struct{}{"US": {}, "UK": {}}, true))
}

func TestCloudflareState_computeExpression(t *testing.T) {
	state := &CloudflareState{
		IPListState:         IPListState{IPList: &cloudflare.IPList{Name: "crowdsec_block"}},
		AutonomousSystemSet: map[string]struct{}{"1234": {}, "5432": {}},
		CountrySet:          map[string]struct{}{"US": {}, "UK": {}},
	}
	require.Equal(t, `(ip.geoip.country in {"UK" "US"}) or (ip.geoip.asnum in {1234 5432}) or (ip.src in $crowdsec_block)`, state.computeExpression())
}

func Test_normalizeIP(t *testing.T) {
	got, err := normalizeDecisionValue("1.2.3.4")
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", got)
	got, err = normalizeDecisionValue("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	require.NoError(t, err)
	require.Equal(t, "2001:db8:85a3::/64", got)
}
