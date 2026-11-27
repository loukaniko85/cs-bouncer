package cfg

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	TokenFile           string       `yaml:"token_file"`
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
	CAFile              string          `yaml:"ca_file"`
	MaxCountryDecisions int             `yaml:"max_country_decisions"`
	MaxASDecisions      int             `yaml:"max_as_decisions"`
}
type UnifiConfig struct {
	Enabled            bool          `yaml:"enabled"`
	Mode               string        `yaml:"mode"`
	URL                string        `yaml:"url"`
	ConsoleID          string        `yaml:"console_id"`
	APIKey             string        `yaml:"api_key"`
	APIKeyFile         string        `yaml:"api_key_file"`
	Site               string        `yaml:"site"`
	ListName           string        `yaml:"list_name"`
	MaxItems           int           `yaml:"max_items"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	CAFile             string        `yaml:"ca_file"`
	AllowInsecureHTTP  bool          `yaml:"allow_insecure_http"`
	UpdateFrequency    time.Duration `yaml:"update_frequency"`
}

func defaultUnifiConfig() UnifiConfig {
	return UnifiConfig{
		Mode:               "local",
		Site:               "default",
		ListName:           "CrowdSec_Blocklist",
		MaxItems:           10000,
		InsecureSkipVerify: false,
		UpdateFrequency:    5 * time.Minute,
	}
}

func validateUnifiConfig(c UnifiConfig) error {
	if !c.Enabled {
		return nil
	}
	if c.Mode != "local" && c.Mode != "cloud" {
		return fmt.Errorf("unifi.mode must be local or cloud")
	}
	if c.Mode == "local" && c.URL == "" {
		return fmt.Errorf("unifi.url is required when unifi.mode is local")
	}
	if c.Mode == "cloud" && c.ConsoleID == "" {
		return fmt.Errorf("unifi.console_id is required when unifi.mode is cloud")
	}
	if c.APIKey == "" {
		return fmt.Errorf("unifi.api_key is required when unifi is enabled")
	}
	if c.MaxItems <= 0 {
		return fmt.Errorf("unifi.max_items must be positive")
	}
	if c.UpdateFrequency <= 0 {
		return fmt.Errorf("unifi.update_frequency must be positive")
	}
	if strings.HasPrefix(c.URL, "http://") && !c.AllowInsecureHTTP {
		return fmt.Errorf("unifi.allow_insecure_http must be true to use an http URL")
	}
	return nil
}

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type bouncerConfig struct {
	CrowdSecLAPIUrl             string           `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey             string           `yaml:"crowdsec_lapi_key"`
	CrowdSecLAPIKeyFile         string           `yaml:"crowdsec_lapi_key_file"`
	StateFile                   string           `yaml:"state_file"`
	CrowdSecInsecureSkipVerify  bool             `yaml:"crowdsec_insecure_skip_verify"`
	CrowdsecUpdateFrequencyYAML string           `yaml:"crowdsec_update_frequency"`
	IncludeScenariosContaining  []string         `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining  []string         `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom    []string         `yaml:"only_include_decisions_from"`
	CloudflareConfig            CloudflareConfig `yaml:"cloudflare_config"`
	Unifi                       UnifiConfig      `yaml:"unifi"`
	Daemon                      bool             `yaml:"daemon"`
	Logging                     LoggingConfig    `yaml:",inline"`
	PrometheusConfig            PrometheusConfig `yaml:"prometheus"`
	KeyPath                     string           `yaml:"key_path"`
	CertPath                    string           `yaml:"cert_path"`
	CAPath                      string           `yaml:"ca_cert_path"`
}

// RedactSecrets returns YAML with sensitive inline values masked.
func RedactSecrets(content []byte) []byte {
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return []byte("***REDACTED***")
	}
	sensitive := map[string]bool{
		"crowdsec_lapi_key": true,
		"token":             true,
		"password":          true,
		"api_key":           true,
	}
	var redact func(*yaml.Node)
	redact = func(node *yaml.Node) {
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i], node.Content[i+1]
				if sensitive[key.Value] {
					value.Kind = yaml.ScalarNode
					value.Tag = "!!str"
					value.Value = "***REDACTED***"
					value.Content = nil
				}
				redact(value)
			}
			return
		}
		for _, child := range node.Content {
			redact(child)
		}
	}
	redact(&document)
	output, err := yaml.Marshal(&document)
	if err != nil {
		return []byte("***REDACTED***")
	}
	return output
}

// WriteConfigFile atomically writes a config file with owner-only permissions.
func WriteConfigFile(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
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
func readSecretFile(path, field string) (string, error) {
	if path == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	return strings.TrimRight(string(content), "\r\n"), nil
}

func resolveSecretFiles(config *bouncerConfig) error {
	if config.CrowdSecLAPIKey != "" && config.CrowdSecLAPIKeyFile != "" {
		return fmt.Errorf("crowdsec_lapi_key and crowdsec_lapi_key_file are mutually exclusive")
	}
	value, err := readSecretFile(config.CrowdSecLAPIKeyFile, "crowdsec_lapi_key_file")
	if err != nil {
		return err
	}
	if value != "" {
		config.CrowdSecLAPIKey = value
	}
	for i := range config.CloudflareConfig.Accounts {
		account := &config.CloudflareConfig.Accounts[i]
		if account.Token != "" && account.TokenFile != "" {
			return fmt.Errorf("account %s: token and token_file are mutually exclusive", account.ID)
		}
		value, err := readSecretFile(account.TokenFile, "token_file")
		if err != nil {
			return err
		}
		if value != "" {
			account.Token = value
		}
	}
	if config.Unifi.APIKey != "" && config.Unifi.APIKeyFile != "" {
		return fmt.Errorf("unifi.api_key and unifi.api_key_file are mutually exclusive")
	}
	value, err = readSecretFile(config.Unifi.APIKeyFile, "unifi.api_key_file")
	if err != nil {
		return err
	}
	if value != "" {
		config.Unifi.APIKey = value
	}
	return nil
}

func NewConfig(reader io.Reader) (*bouncerConfig, error) {
	config := &bouncerConfig{
		CloudflareConfig: CloudflareConfig{
			UpdateFrequency:     5 * time.Minute,
			FullResyncFrequency: 168 * time.Hour,
			Ranking:             defaultRankingConfig(),
			MaxCountryDecisions: 200,
			MaxASDecisions:      200,
		},
		Unifi: defaultUnifiConfig(),
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	configBuff := csstring.StrictExpand(string(content), os.LookupEnv)
	if start := strings.Index(configBuff, "${"); start >= 0 {
		if end := strings.Index(configBuff[start+2:], "}"); end >= 0 {
			name := configBuff[start+2 : start+2+end]
			return nil, fmt.Errorf("config contains unresolved environment variable %s", name)
		}
		return nil, fmt.Errorf("config contains an unresolved environment variable placeholder")
	}

	decoder := yaml.NewDecoder(strings.NewReader(configBuff))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if err := resolveSecretFiles(config); err != nil {
		return nil, err
	}
	if len(config.CloudflareConfig.Accounts) == 0 {
		return nil, fmt.Errorf("cloudflare_config.accounts must contain at least one account")
	}
	if config.CrowdSecLAPIKey == "" && (config.CertPath == "" || config.KeyPath == "") {
		return nil, fmt.Errorf("crowdsec_lapi_key or both cert_path and key_path are required")
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
	if err := validateUnifiConfig(config.Unifi); err != nil {
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
		if account.ID == "" {
			return nil, fmt.Errorf("account id must not be empty")
		}
		if _, ok := accountIDSet[account.ID]; ok {
			return nil, fmt.Errorf("the account '%s' is duplicated", account.ID)
		}
		accountIDSet[account.ID] = true

		if account.Token == "" {
			return nil, fmt.Errorf("the account '%s' is missing token", account.ID)
		}

		if account.TotalIPListCapacity == nil {
			config.CloudflareConfig.Accounts[i].TotalIPListCapacity = &TotalIPListCapacity
		} else if *account.TotalIPListCapacity <= 0 {
			return nil, fmt.Errorf("account %s total_ip_list_capacity must be positive", account.ID)
		}
		if config.CloudflareConfig.MaxCountryDecisions <= 0 || config.CloudflareConfig.MaxASDecisions <= 0 {
			return nil, fmt.Errorf("max_country_decisions and max_as_decisions must be positive")
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
			if zone.ID == "" {
				return nil, fmt.Errorf("account %s has an empty zone id", account.ID)
			}
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
		for _, account := range accounts {
			accountIndex := len(accountConfig)
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
					accountConfig[accountIndex].ZoneConfigs = append(accountConfig[accountIndex].ZoneConfigs, ZoneConfig{
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
	cfg.Unifi = defaultUnifiConfig()

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
