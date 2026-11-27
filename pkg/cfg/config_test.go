package cfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

func TestNewConfig(t *testing.T) {
	type args struct {
		configPath string
	}
	tests := []struct {
		name    string
		args    args
		want    *bouncerConfig
		wantErr string
	}{
		{
			name: "valid",
			args: args{"./testdata/valid_config.yaml"},
			want: &bouncerConfig{
				CrowdSecLAPIUrl:             "http://localhost:8080/",
				CrowdSecLAPIKey:             "test",
				CrowdsecUpdateFrequencyYAML: "10s",
				CloudflareConfig: CloudflareConfig{
					Accounts: []AccountConfig{
						{
							ID:                  "test",
							TotalIPListCapacity: &TotalIPListCapacity,
							ZoneConfigs: []ZoneConfig{
								{
									ID:      "test",
									Actions: []string{"challenge"},
									ActionSet: map[string]struct{}{
										"challenge": {},
									},
								},
							},
							Token:         "test",
							IPListPrefix:  "crowdsec",
							IPListName:    "wafblocklist",
							DefaultAction: "challenge",
						},
					},
					UpdateFrequency:     time.Second * 30,
					FullResyncFrequency: 168 * time.Hour,
					Ranking:             expandedDefaultRanking(),
					MaxCountryDecisions: 200,
					MaxASDecisions:      200,
				},
				Unifi:  defaultUnifiConfig(),
				Daemon: false,
				Logging: LoggingConfig{
					LogMode:      "stdout",
					LogDir:       "/var/log/",
					LogLevel:     ptr.Of(log.InfoLevel),
					LogMaxSize:   40,
					LogMaxFiles:  3,
					LogMaxAge:    30,
					CompressLogs: ptr.Of(true),
				},
			},
		},
		{
			name:    "invalid time",
			args:    args{"./testdata/invalid_config_time.yaml"},
			wantErr: "failed to unmarshal: yaml: unmarshal errors:\n  line 18: cannot unmarshal !!str `blah` into time.Duration",
		},
		{
			name:    "invalid time",
			args:    args{"./testdata/invalid_config_remedy.yaml"},
			wantErr: "zone test doesn't support the default action challenge for it's account",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := os.Open(tt.args.configPath)
			require.NoError(t, err)
			got, err := NewConfig(reader)
			cstest.RequireErrorContains(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)
		})
	}
}

func expandedDefaultRanking() RankingConfig {
	r := defaultRankingConfig()
	for i := range r.Patterns {
		r.Patterns[i].Pattern = expandYear(r.Patterns[i].Pattern)
	}
	return r
}

const minimalConfigYAML = `
crowdsec_lapi_url: http://localhost:8080/
crowdsec_lapi_key: test
cloudflare_config:
  accounts:
  - id: test
    token: test
    default_action: block
    zones:
    - zone_id: test
      actions: [block]
log_mode: stdout
`

func TestTopLevelRankingAlias(t *testing.T) {
	yaml := "ranking:\n  origin_scores:\n    cscli: 20\n" + minimalConfigYAML
	config, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Equal(t, 20, config.CloudflareConfig.Ranking.OriginScores["cscli"])
	require.Equal(t, 10, config.CloudflareConfig.Ranking.OriginScores["CAPI"])
}

func TestLegacyLogMaxBackupsAlias(t *testing.T) {
	yaml := strings.Replace(minimalConfigYAML, "log_mode: stdout", "log_mode: stdout\nlog_max_backups: 7", 1)
	config, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Equal(t, 7, config.Logging.LogMaxFiles)
}

func TestGeneratedCloudflareConfigDefaults(t *testing.T) {
	config := generatedCloudflareConfig(nil)
	require.Equal(t, 200, config.MaxCountryDecisions)
	require.Equal(t, 200, config.MaxASDecisions)
}

func TestSampleConfigsParse(t *testing.T) {
	t.Setenv("API_KEY", "test")
	t.Setenv("CF_ACC_ID", "test")
	t.Setenv("CF_TOKEN", "test")
	t.Setenv("CF_ZONE_ID", "test")
	for _, path := range []string{"../../config/crowdsec-cloudflare-bouncer.yaml", "../../config/crowdsec-cloudflare-bouncer-docker.yaml"} {
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		_, err = NewConfig(strings.NewReader(string(content)))
		require.NoError(t, err, path)
	}
}

func TestRedactSecrets(t *testing.T) {
	input := []byte(`crowdsec_lapi_key: lapi-secret
cloudflare_config:
  accounts:
  - id: test
    token: cf-secret
unifi:
  password: unifi-secret
  username: admin
`)
	output := string(RedactSecrets(input))
	require.NotContains(t, output, "lapi-secret")
	require.NotContains(t, output, "cf-secret")
	require.NotContains(t, output, "unifi-secret")
	require.Contains(t, output, "admin")
	require.Contains(t, output, "REDACTED")

	placeholder := string(RedactSecrets([]byte("crowdsec_lapi_key: ${API_KEY}\n")))
	require.Contains(t, placeholder, "${API_KEY}")
}

func TestWriteConfigFileUses0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, WriteConfigFile(path, []byte("secret: value\n")))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestConfigHardening(t *testing.T) {
	t.Run("unknown field", func(t *testing.T) {
		_, err := NewConfig(strings.NewReader("unknown_key: value\n" + minimalConfigYAML))
		require.ErrorContains(t, err, "unknown_key")
	})
	t.Run("no accounts", func(t *testing.T) {
		_, err := NewConfig(strings.NewReader("crowdsec_lapi_url: http://localhost:8080/\ncrowdsec_lapi_key: test\n"))
		require.ErrorContains(t, err, "at least one")
	})
	t.Run("empty account id", func(t *testing.T) {
		yaml := strings.Replace(minimalConfigYAML, "id: test", "id: ''", 1)
		_, err := NewConfig(strings.NewReader(yaml))
		require.ErrorContains(t, err, "account id")
	})
	t.Run("empty zone id", func(t *testing.T) {
		yaml := strings.Replace(minimalConfigYAML, "- zone_id: test\n      actions", "- zone_id: ''\n      actions", 1)
		_, err := NewConfig(strings.NewReader(yaml))
		require.ErrorContains(t, err, "zone id")
	})
	t.Run("unresolved env", func(t *testing.T) {
		yaml := strings.Replace(minimalConfigYAML, "crowdsec_lapi_key: test", "crowdsec_lapi_key: ${MISSING_TEST_VAR}", 1)
		_, err := NewConfig(strings.NewReader(yaml))
		require.ErrorContains(t, err, "MISSING_TEST_VAR")
	})
	t.Run("negative capacity", func(t *testing.T) {
		yaml := strings.Replace(minimalConfigYAML, "default_action: block", "default_action: block\n    total_ip_list_capacity: -1", 1)
		_, err := NewConfig(strings.NewReader(yaml))
		require.ErrorContains(t, err, "total_ip_list_capacity")
	})
	t.Run("missing lapi auth", func(t *testing.T) {
		yaml := strings.Replace(minimalConfigYAML, "crowdsec_lapi_key: test\n", "", 1)
		_, err := NewConfig(strings.NewReader(yaml))
		require.ErrorContains(t, err, "crowdsec_lapi_key")
	})
	t.Run("mtls without api key", func(t *testing.T) {
		yaml := strings.Replace(minimalConfigYAML, "crowdsec_lapi_key: test\n", "cert_path: /tmp/cert\nkey_path: /tmp/key\n", 1)
		_, err := NewConfig(strings.NewReader(yaml))
		require.NoError(t, err)
	})
	t.Run("unifi secure defaults", func(t *testing.T) {
		c, err := NewConfig(strings.NewReader(minimalConfigYAML))
		require.NoError(t, err)
		require.False(t, c.Unifi.InsecureSkipVerify)
		require.False(t, c.Unifi.AllowInsecureHTTP)
		require.Equal(t, 200, c.CloudflareConfig.MaxCountryDecisions)
		require.Equal(t, 200, c.CloudflareConfig.MaxASDecisions)
	})
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(value+"\n"), 0600))
		return path
	}
	lapiFile := write("lapi", "lapi-from-file")
	tokenFile := write("token", "token-from-file")
	apiKeyFile := write("api-key", "api-key-from-file")

	yaml := fmt.Sprintf(`crowdsec_lapi_url: http://localhost:8080/
crowdsec_lapi_key_file: %s
cloudflare_config:
  accounts:
  - id: test
    token_file: %s
    default_action: block
    zones:
    - zone_id: test
      actions: [block]
unifi:
  enabled: true
  url: https://10.0.24.1
  api_key_file: %s
`, lapiFile, tokenFile, apiKeyFile)
	c, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Equal(t, "lapi-from-file", c.CrowdSecLAPIKey)
	require.Equal(t, "token-from-file", c.CloudflareConfig.Accounts[0].Token)
	require.Equal(t, "api-key-from-file", c.Unifi.APIKey)

	both := strings.Replace(yaml, "crowdsec_lapi_key_file:", "crowdsec_lapi_key: inline\ncrowdsec_lapi_key_file:", 1)
	_, err = NewConfig(strings.NewReader(both))
	require.ErrorContains(t, err, "crowdsec_lapi_key_file")

	missing := strings.Replace(yaml, lapiFile, filepath.Join(dir, "absent"), 1)
	_, err = NewConfig(strings.NewReader(missing))
	require.ErrorContains(t, err, "absent")
}

func TestStateFileDefaultAndOverride(t *testing.T) {
	c, err := NewConfig(strings.NewReader(minimalConfigYAML))
	require.NoError(t, err)
	require.Empty(t, c.StateFile)

	c, err = NewConfig(strings.NewReader("state_file: /var/lib/cs/state_{account}.json\n" + minimalConfigYAML))
	require.NoError(t, err)
	require.Equal(t, "/var/lib/cs/state_{account}.json", c.StateFile)
}

func TestNewConfigUnifiDefaults(t *testing.T) {
	c, err := NewConfig(strings.NewReader(minimalConfigYAML))
	require.NoError(t, err)
	require.False(t, c.Unifi.Enabled)
	require.Equal(t, "default", c.Unifi.Site)
	require.Equal(t, "CrowdSec_Blocklist", c.Unifi.ListName)
	require.Equal(t, 10000, c.Unifi.MaxItems)
	require.Equal(t, 5*time.Minute, c.Unifi.UpdateFrequency)
	require.False(t, c.Unifi.InsecureSkipVerify)
}

func TestNewConfigUnifiValidation(t *testing.T) {
	cases := []struct {
		name    string
		patch   string
		wantErr string
	}{
		{"missing url", "unifi:\n  enabled: true\n  api_key: k\n", "unifi.url"},
		{"missing api key", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n", "unifi.api_key"},
		{"missing console id", "unifi:\n  enabled: true\n  mode: cloud\n  api_key: k\n", "unifi.console_id"},
		{"zero max items", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  api_key: k\n  max_items: 0\n", "unifi.max_items"},
		{"zero frequency", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  api_key: k\n  update_frequency: 0s\n", "unifi.update_frequency"},
		{"empty site", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  api_key: k\n  site: ''\n", "unifi.site"},
		{"empty list", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  api_key: k\n  list_name: ''\n", "unifi.list_name"},
		{"bad url", "unifi:\n  enabled: true\n  url: not-a-url\n  api_key: k\n", "unifi.url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := tc.patch + minimalConfigYAML
			_, err := NewConfig(strings.NewReader(yaml))
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestNewConfigUnifiEnabled(t *testing.T) {
	t.Setenv("UNIFI_API_KEY", "secret")
	yaml := `unifi:
  enabled: true
  url: https://10.0.24.1
  api_key: ${UNIFI_API_KEY}
  list_name: My_Block
  max_items: 500
  update_frequency: 10m
  insecure_skip_verify: false
` + minimalConfigYAML
	c, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.True(t, c.Unifi.Enabled)
	require.Equal(t, "https://10.0.24.1", c.Unifi.URL)
	require.Equal(t, "My_Block", c.Unifi.ListName)
	require.Equal(t, 500, c.Unifi.MaxItems)
	require.Equal(t, 10*time.Minute, c.Unifi.UpdateFrequency)
	require.False(t, c.Unifi.InsecureSkipVerify)
	require.Equal(t, "secret", c.Unifi.APIKey)
}

func TestNewConfigRankingDefaults(t *testing.T) {
	c, err := NewConfig(strings.NewReader(minimalConfigYAML))
	require.NoError(t, err)
	require.Equal(t, 5*time.Minute, c.CloudflareConfig.UpdateFrequency)
	require.Equal(t, 168*time.Hour, c.CloudflareConfig.FullResyncFrequency)
	require.Len(t, c.CloudflareConfig.Ranking.Patterns, 4)
	require.Equal(t, 100, c.CloudflareConfig.Ranking.Patterns[0].Score)
	require.Contains(t, c.CloudflareConfig.Ranking.Patterns[0].Pattern, strconv.Itoa(time.Now().Year()))
	require.Equal(t, 20, c.CloudflareConfig.Ranking.TypeScores["ban"])
	require.Equal(t, "wafblocklist", c.CloudflareConfig.Accounts[0].IPListName)
}

func TestNewConfigRankingValidation(t *testing.T) {
	cases := []struct {
		name    string
		patch   string
		wantErr string
	}{
		{"bad regex", "  ranking:\n    patterns:\n    - name: bad\n      pattern: '(' \n      score: 10\n", "ranking.patterns[0].pattern"},
		{"negative score", "  ranking:\n    patterns:\n    - name: bad\n      pattern: foo\n      score: -1\n", "ranking.patterns[0].score"},
		{"zero update frequency", "  update_frequency: 0s\n", "update_frequency"},
		{"zero resync frequency", "  full_resync_frequency: 0s\n", "full_resync_frequency"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yaml := strings.Replace(minimalConfigYAML, "  accounts:\n", tc.patch+"  accounts:\n", 1)
			_, err := NewConfig(strings.NewReader(yaml))
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestNewConfigRankingPatternsOverride(t *testing.T) {
	yaml := strings.Replace(minimalConfigYAML, "  accounts:\n", `  ranking:
    patterns:
    - name: custom
      pattern: my-scenario
      score: 77
  accounts:
`, 1)
	c, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Len(t, c.CloudflareConfig.Ranking.Patterns, 1)
	require.Equal(t, 77, c.CloudflareConfig.Ranking.Patterns[0].Score)
	require.Equal(t, 20, c.CloudflareConfig.Ranking.TypeScores["ban"])
	require.Equal(t, 10, c.CloudflareConfig.Ranking.OriginScores["CAPI"])

	yamlEmpty := strings.Replace(minimalConfigYAML, "  accounts:\n", "  ranking:\n    patterns: []\n  accounts:\n", 1)
	c, err = NewConfig(strings.NewReader(yamlEmpty))
	require.NoError(t, err)
	require.Len(t, c.CloudflareConfig.Ranking.Patterns, 4)
}
