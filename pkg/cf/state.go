package cf

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
)

var CloudflareActionByDecisionType = map[string]string{
	"captcha":      "managed_challenge",
	"ban":          "block",
	"js_challenge": "js_challenge",
}

// StatePath expands the {account} token in the state file template.
func StatePath(template, accountID string) string {
	return statePath(template, accountID)
}

func statePath(template, accountID string) string {
	return strings.ReplaceAll(template, "{account}", accountID)
}

// SaveState writes the active decision set atomically.

func SaveState(path string, active map[string]map[string]*models.Decision) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	encoded, err := json.Marshal(active)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// LoadState reads a persisted decision set and drops expired decisions.

func LoadState(path string) (map[string]map[string]*models.Decision, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]map[string]*models.Decision), nil
	}
	if err != nil {
		return nil, err
	}
	active := make(map[string]map[string]*models.Decision)
	if err := json.Unmarshal(content, &active); err != nil {
		return nil, err
	}
	now := time.Now()
	for value, decisions := range active {
		for key, decision := range decisions {
			if decision == nil {
				delete(decisions, key)
				continue
			}
			if decision.Until == "" {
				continue
			}
			until, err := time.Parse(time.RFC3339, decision.Until)
			if err == nil && until.Before(now) {
				delete(decisions, key)
			}
		}
		if len(decisions) == 0 {
			delete(active, value)
		}
	}
	return active, nil
}

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

func normalizeDecisionValue(value string) (string, error) {
	if strings.Contains(value, "/") && !strings.Contains(value, ":") {
		host, network, err := net.ParseCIDR(value)
		if err != nil || host.To4() == nil {
			return "", fmt.Errorf("invalid IPv4 value %q", value)
		}
		ones, bits := network.Mask.Size()
		if ones == 32 && bits == 32 {
			return host.String(), nil
		}
		return network.String(), nil
	}
	if !strings.Contains(value, ":") {
		parsed := net.ParseIP(value)
		if parsed == nil || parsed.To4() == nil {
			return "", fmt.Errorf("invalid IPv4 value %q", value)
		}
		return parsed.String(), nil
	}
	if !strings.Contains(value, "/") {
		parsed := net.ParseIP(value)
		if parsed == nil || parsed.To4() != nil {
			return "", fmt.Errorf("invalid IPv6 value %q", value)
		}
		value = parsed.String()
	}
	_, address, err := net.ParseCIDR(value)
	if err != nil {
		_, address, err = net.ParseCIDR(value + "/64")
		if err != nil {
			return "", fmt.Errorf("invalid IPv6 value %q: %w", value, err)
		}
	}
	if ones, _ := address.Mask.Size(); ones < 64 {
		return address.String(), nil
	}
	address.Mask = net.CIDRMask(64, 128)
	return address.String(), nil
}
