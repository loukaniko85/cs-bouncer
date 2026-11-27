package cf

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/rank"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

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
	StatePath           string
	lastStateSave       time.Time
	rankingConfig       cfg.RankingConfig
	Ctx                 context.Context
	Events              chan DecisionEvent
	lastEventSeq        uint64
	UpdateFrequency     time.Duration
	FullResyncFrequency time.Duration
	nextReconcile       time.Time
	API                 cloudflareAPI
	Count               prometheus.Counter
}

// this is useful for testing allowing us to mock it.

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
	worker.saveStateIfDue()
}

func (worker *CloudflareWorker) saveStateIfDue() {
	if worker.StatePath == "" {
		return
	}
	now := time.Now()
	if !worker.lastStateSave.IsZero() && now.Sub(worker.lastStateSave) < 30*time.Second {
		return
	}
	if err := SaveState(worker.StatePath, worker.ActiveDecisions); err != nil {
		if worker.Logger != nil {
			worker.Logger.Warnf("could not persist decision state: %s", err)
		}
		return
	}
	worker.lastStateSave = now
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
	worker.saveStateIfDue()
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
	if worker.StatePath != "" {
		loaded, err := LoadState(worker.StatePath)
		if err != nil {
			worker.Logger.Warnf("could not load decision state: %s", err)
		} else {
			worker.ActiveDecisions = loaded
		}
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
