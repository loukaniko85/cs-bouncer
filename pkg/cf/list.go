package cf

import (
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/rank"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
	if legacy != nil {
		return fmt.Errorf("legacy CrowdSec-managed list %s found; manual migration required: point rules at $%s, delete the legacy list, then restart", legacy.Name, worker.Account.IPListName)
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

func (worker *CloudflareWorker) hydrateListState() error {
	items, err := worker.getAPI().ListIPListItems(worker.Ctx, worker.Account.ID, worker.IPListState.IPList.ID)
	if err != nil {
		return err
	}
	set := make(map[string]IPSetItem, len(items))
	for _, item := range items {
		value, err := normalizeDecisionValue(item.IP)
		if err == nil {
			set[value] = IPSetItem{}
		}
	}
	worker.IPListState.IPSet = set

	lists, err := worker.getAPI().ListIPLists(worker.Ctx, worker.Account.ID)
	if err != nil {
		return err
	}
	otherItems := 0
	for _, list := range lists {
		if list.ID != worker.IPListState.IPList.ID && list.Kind == "ip" {
			otherItems += list.NumItems
		}
	}
	capacity := cfg.TotalIPListCapacity
	if worker.Account.TotalIPListCapacity != nil {
		capacity = *worker.Account.TotalIPListCapacity
	}
	worker.EffectiveCapacity = capacity - otherItems
	if worker.EffectiveCapacity <= 0 {
		return fmt.Errorf("no Cloudflare list capacity remains: configured=%d other_ip_list_items=%d", capacity, otherItems)
	}
	worker.Logger.Infof("effective IP list capacity: %d (configured=%d other_ip_list_items=%d)", worker.EffectiveCapacity, capacity, otherItems)
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
			select {
			case <-worker.Ctx.Done():
				return worker.Ctx.Err()
			case <-time.After(time.Second):
			}
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

func (worker *CloudflareWorker) publishRankedIPs(ips []string) {
	if worker.BlocklistListener == nil {
		return
	}
	worker.BlocklistListener.Publish(worker.Account.ID, ips)
}

// RankDecisions applies the full selection pipeline used by the blocklist:
// IP/RANGE scope filter, normalization, dedup, severity ranking and capacity.

func RankDecisions(decisions []*models.Decision, r *rank.Ranker, capacity int, now time.Time) []string {
	normalized := make([]*models.Decision, 0, len(decisions))
	for _, d := range decisions {
		if d == nil || d.Value == nil || d.Scope == nil {
			continue
		}
		scope := strings.ToUpper(*d.Scope)
		if scope != "IP" && scope != "RANGE" {
			continue
		}
		copyOfDecision := *d
		value, err := normalizeDecisionValue(*d.Value)
		if err != nil {
			continue
		}
		copyOfDecision.Value = &value
		normalized = append(normalized, &copyOfDecision)
	}
	ranked := r.Rank(normalized, now)
	if len(ranked) > capacity {
		RankingDroppedTotal.Add(float64(len(ranked) - capacity))
		ranked = ranked[:capacity]
	}
	ips := make([]string, 0, len(ranked))
	for _, d := range ranked {
		ips = append(ips, *d.Value)
	}
	return ips
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

	capacity := worker.EffectiveCapacity
	if capacity <= 0 {
		capacity = cfg.TotalIPListCapacity
		if worker.Account.TotalIPListCapacity != nil {
			capacity = *worker.Account.TotalIPListCapacity
		}
	}
	values := RankDecisions(ipDecisions, worker.Ranker, capacity, now)
	worker.publishRankedIPs(values)

	newSet := make(map[string]IPSetItem, len(values))
	for _, value := range values {
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

func validCountry(value string) bool {
	if len(value) != 2 {
		return false
	}
	return value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func validASN(value string) bool {
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}

func (worker *CloudflareWorker) rankedScopedValues(values map[string]*models.Decision, limit int) []string {
	items := make([]*models.Decision, 0, len(values))
	for _, decision := range values {
		items = append(items, decision)
	}
	now := time.Now()
	sort.Slice(items, func(i, j int) bool {
		si, sj := worker.Ranker.Score(items[i], now), worker.Ranker.Score(items[j], now)
		if si != sj {
			return si > sj
		}
		startI, startJ := worker.Ranker.StartTime(items[i]), worker.Ranker.StartTime(items[j])
		if !startI.Equal(startJ) {
			return startI.After(startJ)
		}
		return *items[i].Value < *items[j].Value
	})
	if len(items) > limit {
		ScopedDecisionsDroppedTotal.Add(float64(len(items) - limit))
		items = items[:limit]
	}
	result := make([]string, 0, len(items))
	for _, decision := range items {
		result = append(result, *decision.Value)
	}
	return result
}

func (worker *CloudflareWorker) refreshScopedSets() {
	countries := make(map[string]map[string]*models.Decision)
	asns := make(map[string]map[string]*models.Decision)
	for _, decisions := range worker.ActiveDecisions {
		for _, d := range decisions {
			if d == nil || d.Scope == nil || d.Value == nil || d.Type == nil || (d.Simulated != nil && *d.Simulated) {
				continue
			}
			action := CloudflareActionByDecisionType[*d.Type]
			if action == "" || !allZonesHaveAction(worker.Account.ZoneConfigs, action) {
				action = worker.Account.DefaultAction
			}
			if worker.CFStateByAction[action] == nil {
				continue
			}
			switch strings.ToUpper(*d.Scope) {
			case "COUNTRY":
				value := strings.ToUpper(*d.Value)
				if !validCountry(value) {
					continue
				}
				if countries[action] == nil {
					countries[action] = make(map[string]*models.Decision)
				}
				countries[action][value] = d
			case "AS":
				if !validASN(*d.Value) {
					continue
				}
				if asns[action] == nil {
					asns[action] = make(map[string]*models.Decision)
				}
				asns[action][*d.Value] = d
			}
		}
	}
	countryLimit := worker.MaxCountryDecisions
	if countryLimit <= 0 {
		countryLimit = 200
	}
	asLimit := worker.MaxASDecisions
	if asLimit <= 0 {
		asLimit = 200
	}
	for action, state := range worker.CFStateByAction {
		state.CountrySet = make(map[string]struct{})
		for _, value := range worker.rankedScopedValues(countries[action], countryLimit) {
			state.CountrySet[value] = struct{}{}
		}
		state.AutonomousSystemSet = make(map[string]struct{})
		for _, value := range worker.rankedScopedValues(asns[action], asLimit) {
			state.AutonomousSystemSet[value] = struct{}{}
		}
	}
}
