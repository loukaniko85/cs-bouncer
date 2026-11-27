package cfg

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
)

var TotalIPListCapacity int = 10000

type RankingPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Score   int    `yaml:"score"`
}

type RankingConfig struct {
	Patterns             []RankingPattern `yaml:"patterns"`
	DefaultScore         int              `yaml:"default_score"`
	TypeScores           map[string]int   `yaml:"type_scores"`
	DurationBonusPerHour int              `yaml:"duration_bonus_per_hour"`
	DurationBonusMax     int              `yaml:"duration_bonus_max"`
	OriginScores         map[string]int   `yaml:"origin_scores"`
}

func defaultRankingConfig() RankingConfig {
	return RankingConfig{
		Patterns: []RankingPattern{
			{Name: "zero_day", Pattern: `(?i)(0day|zero.?day|cve-{{YEAR}})`, Score: 100},
			{Name: "exploit", Pattern: `(?i)(exploit|rce|sqli|lfi|xxe|ssrf|webshell)`, Score: 80},
			{Name: "brute_force", Pattern: `(?i)(bf|brute|credential|spray)`, Score: 40},
			{Name: "scanning", Pattern: `(?i)(scan|probe|crawl|bot)`, Score: 10},
		},
		DefaultScore:         20,
		TypeScores:           map[string]int{"ban": 20, "captcha": 5, "js_challenge": 5, "challenge": 5},
		DurationBonusPerHour: 1,
		DurationBonusMax:     20,
		OriginScores:         map[string]int{"crowdsec": 10, "CAPI": 10, "cscli": 0, "lists": 0},
	}
}

func expandYear(pattern string) string {
	return strings.ReplaceAll(pattern, "{{YEAR}}", strconv.Itoa(time.Now().Year()))
}

func validateRankingConfig(ranking RankingConfig) error {
	if ranking.DefaultScore < 0 {
		return fmt.Errorf("ranking.default_score must be non-negative")
	}
	if ranking.DurationBonusPerHour < 0 {
		return fmt.Errorf("ranking.duration_bonus_per_hour must be non-negative")
	}
	if ranking.DurationBonusMax < 0 {
		return fmt.Errorf("ranking.duration_bonus_max must be non-negative")
	}
	for i, pattern := range ranking.Patterns {
		if pattern.Name == "" {
			return fmt.Errorf("ranking.patterns[%d].name is required", i)
		}
		if _, err := regexp.Compile(expandYear(pattern.Pattern)); err != nil {
			return fmt.Errorf("ranking.patterns[%d].pattern: %w", i, err)
		}
		if pattern.Score < 0 {
			return fmt.Errorf("ranking.patterns[%d].score must be non-negative", i)
		}
	}
	for name, score := range ranking.TypeScores {
		if score < 0 {
			return fmt.Errorf("ranking.type_scores[%s] must be non-negative", name)
		}
	}
	for name, score := range ranking.OriginScores {
		if score < 0 {
			return fmt.Errorf("ranking.origin_scores[%s] must be non-negative", name)
		}
	}
	return nil
}

type ZoneConfig struct {
	ID        string              `yaml:"zone_id"`
	Actions   []string            `yaml:"actions,omitempty"`
	ActionSet map[string]struct{} `yaml:",omitempty"`
}
type AccountConfig struct {
	ID                  string       `yaml:"id"`
	ZoneConfigs         []ZoneConfig `yaml:"zones"`
	Token               string       `yaml:"token"`
	IPListPrefix        string       `yaml:"ip_list_prefix"`
	IPListName          string       `yaml:"ip_list_name"`
	DefaultAction       string       `yaml:"default_action"`
	TotalIPListCapacity *int         `yaml:"total_ip_list_capacity"`
}
type CloudflareConfig struct {
	Accounts            []AccountConfig `yaml:"accounts"`
	UpdateFrequency     time.Duration   `yaml:"update_frequency"`
	FullResyncFrequency time.Duration   `yaml:"full_resync_frequency"`
	Ranking             RankingConfig   `yaml:"ranking"`
}
type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type bouncerConfig struct {
	CrowdSecLAPIUrl             string           `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey             string           `yaml:"crowdsec_lapi_key"`
	CrowdSecInsecureSkipVerify  bool             `yaml:"crowdsec_insecure_skip_verify"`
	CrowdsecUpdateFrequencyYAML string           `yaml:"crowdsec_update_frequency"`
	IncludeScenariosContaining  []string         `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining  []string         `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom    []string         `yaml:"only_include_decisions_from"`
	CloudflareConfig            CloudflareConfig `yaml:"cloudflare_config"`
	Daemon                      bool             `yaml:"daemon"`
	Logging                     LoggingConfig    `yaml:",inline"`
	PrometheusConfig            PrometheusConfig `yaml:"prometheus"`
	KeyPath                     string           `yaml:"key_path"`
	CertPath                    string           `yaml:"cert_path"`
	CAPath                      string           `yaml:"ca_cert_path"`
}

func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")
	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// NewConfig creates bouncerConfig from the file at provided path
func NewConfig(reader io.Reader) (*bouncerConfig, error) {
	config := &bouncerConfig{
		CloudflareConfig: CloudflareConfig{
			UpdateFrequency:     5 * time.Minute,
			FullResyncFrequency: 168 * time.Hour,
			Ranking:             defaultRankingConfig(),
		},
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	configBuff := csstring.StrictExpand(string(content), os.LookupEnv)

	err = yaml.Unmarshal([]byte(configBuff), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if len(config.CloudflareConfig.Ranking.Patterns) == 0 {
		config.CloudflareConfig.Ranking.Patterns = defaultRankingConfig().Patterns
		log.Warn("ranking.patterns is empty, using defaults")
	}
	for i := range config.CloudflareConfig.Ranking.Patterns {
		config.CloudflareConfig.Ranking.Patterns[i].Pattern = expandYear(config.CloudflareConfig.Ranking.Patterns[i].Pattern)
	}
	if config.CloudflareConfig.UpdateFrequency <= 0 {
		return nil, fmt.Errorf("cloudflare_config.update_frequency must be positive")
	}
	if config.CloudflareConfig.FullResyncFrequency <= 0 {
		return nil, fmt.Errorf("cloudflare_config.full_resync_frequency must be positive")
	}
	if err := validateRankingConfig(config.CloudflareConfig.Ranking); err != nil {
		return nil, err
	}

	if err = config.Logging.setup("crowdsec-cloudflare-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	accountIDSet := make(map[string]bool) // for verifying that each account ID is unique
	zoneIDSet := make(map[string]bool)    // for verifying that each zoneID is unique
	validAction := map[string]bool{"challenge": true, "block": true, "js_challenge": true, "managed_challenge": true}
	validChoiceMsg := "valid choices are either of 'block', 'js_challenge', 'challenge', 'managed_challenge'"

	for i, account := range config.CloudflareConfig.Accounts {
		if _, ok := accountIDSet[account.ID]; ok {
			return nil, fmt.Errorf("the account '%s' is duplicated", account.ID)
		}
		accountIDSet[account.ID] = true

		if account.Token == "" {
			return nil, fmt.Errorf("the account '%s' is missing token", account.ID)
		}

		if account.TotalIPListCapacity == nil {
			config.CloudflareConfig.Accounts[i].TotalIPListCapacity = &TotalIPListCapacity
		}
		if account.IPListPrefix == "" {
			config.CloudflareConfig.Accounts[i].IPListPrefix = "crowdsec"
		}
		if account.IPListName == "" {
			// Cloudflare limits lists that look CrowdSec-managed to one bulk
			// update per 24h; a neutral name allows frequent updates.
			config.CloudflareConfig.Accounts[i].IPListName = "wafblocklist"
		}

		if len(account.DefaultAction) == 0 {
			return nil, fmt.Errorf("account %s has no default action", account.ID)
		}
		if _, ok := validAction[account.DefaultAction]; !ok {
			return nil, fmt.Errorf("account %s 's default action is invalid. %s ", account.ID, validChoiceMsg)
		}
		zoneUsingChallenge := make([]string, 0)
		for j, zone := range account.ZoneConfigs {
			config.CloudflareConfig.Accounts[i].ZoneConfigs[j].ActionSet = map[string]struct{}{}
			if len(zone.Actions) == 0 {
				return nil, fmt.Errorf("account %s 's zone %s has no action", account.ID, zone.ID)
			}
			defaultActionIsSupported := false
			for _, a := range zone.Actions {
				if _, ok := validAction[a]; !ok {
					return nil, fmt.Errorf("invalid actions '%s', %s", a, validChoiceMsg)
				}
				if a == "challenge" {
					zoneUsingChallenge = append(zoneUsingChallenge, zone.ID)
				}
				if a == account.DefaultAction {
					defaultActionIsSupported = true
				}
				config.CloudflareConfig.Accounts[i].ZoneConfigs[j].ActionSet[a] = struct{}{}
			}

			if !defaultActionIsSupported {
				return nil, fmt.Errorf("zone %s doesn't support the default action %s for it's account", zone.ID, account.DefaultAction)
			}

			if _, ok := zoneIDSet[zone.ID]; ok {
				return nil, fmt.Errorf("zone id %s is duplicated", zone.ID)
			}
			zoneIDSet[zone.ID] = true
		}
		if len(zoneUsingChallenge) > 0 {
			log.Warningf(
				"zones %s uses 'challenge' action which is deprecated in favour of 'managed_challenge'. See migration guide at https://docs.crowdsec.net/docs/next/bouncers/cloudflare/#upgrading-from-v00x-to-v01y",
				strings.Join(zoneUsingChallenge, ", "),
			)
		}
	}
	return config, nil
}

func lineComment(l string, zoneByID map[string]cloudflare.Zone, accountByID map[string]cloudflare.Account) string {
	words := strings.Split(l, " ")
	lastWord := words[len(words)-1]
	if zone, ok := zoneByID[lastWord]; ok {
		return zone.Name
	}
	if account, ok := accountByID[lastWord]; ok {
		return account.Name
	}
	if strings.Contains(l, "total_ip_list_capacity") {
		return "only this many latest IP decisions would be kept"
	}
	if strings.Contains(l, "exclude_scenarios_containing") {
		return "ignore IPs banned for triggering scenarios containing either of provided word"
	}
	if strings.Contains(l, "include_scenarios_containing") {
		return "ignore IPs banned for triggering scenarios not containing either of provided word"
	}
	if strings.Contains(l, "only_include_decisions_from") {
		return `only include IPs banned due to decisions orginating from provided sources. eg value ["cscli", "crowdsec"]`
	}
	return ""
}

func ConfigTokens(tokens string, baseConfigPath string) (string, error) {
	baseConfig := &bouncerConfig{}
	hasBaseConfig := true
	configBuff, err := os.ReadFile(baseConfigPath)
	if err != nil {
		hasBaseConfig = false
	}

	if hasBaseConfig {
		err = yaml.Unmarshal(configBuff, &baseConfig)
		if err != nil {
			return "", err
		}
	} else {
		setDefaults(baseConfig)
	}

	accountConfig := make([]AccountConfig, 0)
	zoneByID := make(map[string]cloudflare.Zone)
	accountByID := make(map[string]cloudflare.Account)
	ctx := context.Background()
	for _, token := range strings.Split(tokens, ",") {
		api, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			return "", err
		}
		accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
		if err != nil {
			return "", err
		}
		for i, account := range accounts {
			accountConfig = append(accountConfig, AccountConfig{
				ID:                  account.ID,
				ZoneConfigs:         make([]ZoneConfig, 0),
				Token:               token,
				IPListPrefix:        "crowdsec",
				IPListName:          "wafblocklist",
				DefaultAction:       "managed_challenge",
				TotalIPListCapacity: &TotalIPListCapacity,
			})

			accountByID[account.ID] = account
			zones, err := api.ListZones(ctx)
			if err != nil {
				return "", err
			}

			for _, zone := range zones {
				zoneByID[zone.ID] = zone
				if zone.Account.ID == account.ID {
					accountConfig[i].ZoneConfigs = append(accountConfig[i].ZoneConfigs, ZoneConfig{
						ID:      zone.ID,
						Actions: []string{"managed_challenge"},
					})
				}
			}
		}
	}
	cfConfig := CloudflareConfig{
		Accounts:            accountConfig,
		UpdateFrequency:     time.Second * 10,
		FullResyncFrequency: 168 * time.Hour,
		Ranking:             defaultRankingConfig(),
	}
	baseConfig.CloudflareConfig = cfConfig
	data, err := yaml.Marshal(baseConfig)
	if err != nil {
		return "", err
	}

	lineString := string(data)
	lines := strings.Split(lineString, "\n")
	if hasBaseConfig {
		lines = append([]string{
			fmt.Sprintf("# Config generated by using %s as base", baseConfigPath),
		},
			lines...,
		)
	} else {
		lines = append([]string{
			fmt.Sprintf("# Base config %s not found, please fill crowdsec credentials. ", baseConfigPath),
		},
			lines...,
		)
	}
	for i, line := range lines {
		comment := lineComment(line, zoneByID, accountByID)
		if comment != "" {
			lines[i] = line + " # " + comment
		}
	}

	return strings.Join(lines, "\n"), nil
}

func setDefaults(cfg *bouncerConfig) {
	cfg.CrowdSecLAPIUrl = "http://localhost:8080/"
	cfg.CrowdsecUpdateFrequencyYAML = "10s"

	cfg.Daemon = true
	cfg.ExcludeScenariosContaining = []string{
		"ssh",
		"ftp",
		"smb",
	}
	cfg.OnlyIncludeDecisionsFrom = []string{
		"CAPI",
		"cscli",
		"crowdsec",
		"lists",
	}

	cfg.PrometheusConfig = PrometheusConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    "2112",
	}
}
