package cf

import (
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"strings"
)

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

func (worker *CloudflareWorker) SetUpCloudflareResources() error {
	if err := worker.importExistingIPLists(); err != nil {
		return err
	}
	if err := worker.createMissingIPLists(); err != nil {
		return err
	}
	if err := worker.hydrateListState(); err != nil {
		return err
	}
	for _, state := range worker.CFStateByAction {
		state.IPListState = worker.IPListState
		state.UpdateExpr()
	}
	return nil
}

// Setup creates the list and its rules (used by the -s CLI flag).
