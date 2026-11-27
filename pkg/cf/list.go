package cf

import (
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/rank"
	"reflect"
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
		value := normalizeDecisionValue(*d.Value)
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

	capacity := cfg.TotalIPListCapacity
	if worker.Account.TotalIPListCapacity != nil {
		capacity = *worker.Account.TotalIPListCapacity
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
