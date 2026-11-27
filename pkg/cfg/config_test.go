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
				},
				Unifi:    defaultUnifiConfig(),
				Daemon:   false,
				Logging: LoggingConfig{
					LogMode:  "stdout",
					LogDir:   "/var/log/",
					LogLevel: ptr.Of(log.InfoLevel),
					LogMaxSize: 40,
					LogMaxFiles: 3,
					LogMaxAge: 30,
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
    - id: test
      actions: [block]
log_mode: stdout
`

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(value+"\n"), 0600))
		return path
	}
	lapiFile := write("lapi", "lapi-from-file")
	tokenFile := write("token", "token-from-file")
	passwordFile := write("password", "password-from-file")

	yaml := fmt.Sprintf(`crowdsec_lapi_url: http://localhost:8080/
crowdsec_lapi_key_file: %s
cloudflare_config:
  accounts:
  - id: test
    token_file: %s
    default_action: block
    zones:
    - id: test
      actions: [block]
unifi:
  enabled: true
  url: https://10.0.24.1
  username: admin
  password_file: %s
`, lapiFile, tokenFile, passwordFile)
	c, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.Equal(t, "lapi-from-file", c.CrowdSecLAPIKey)
	require.Equal(t, "token-from-file", c.CloudflareConfig.Accounts[0].Token)
	require.Equal(t, "password-from-file", c.Unifi.Password)

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

	c, err = NewConfig(strings.NewReader("state_file: /var/lib/cs/state_{account}.json\n"+minimalConfigYAML))
	require.NoError(t, err)
	require.Equal(t, "/var/lib/cs/state_{account}.json", c.StateFile)
}

func TestNewConfigUnifiDefaults(t *testing.T) {
	c, err := NewConfig(strings.NewReader(minimalConfigYAML))
	require.NoError(t, err)
	require.False(t, c.Unifi.Enabled)
	require.Equal(t, "default", c.Unifi.Site)
	require.Equal(t, "CrowdSec_Block", c.Unifi.GroupName)
	require.Equal(t, 10000, c.Unifi.MaxItems)
	require.Equal(t, 5*time.Minute, c.Unifi.UpdateFrequency)
	require.True(t, c.Unifi.InsecureSkipVerify)
}

func TestNewConfigUnifiValidation(t *testing.T) {
	cases := []struct {
		name    string
		patch   string
		wantErr string
	}{
		{"missing url", "unifi:\n  enabled: true\n  username: u\n  password: p\n", "unifi.url"},
		{"missing username", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  password: p\n", "unifi.username"},
		{"missing password", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  username: u\n", "unifi.password"},
		{"zero max items", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  username: u\n  password: p\n  max_items: 0\n", "unifi.max_items"},
		{"zero frequency", "unifi:\n  enabled: true\n  url: https://10.0.24.1\n  username: u\n  password: p\n  update_frequency: 0s\n", "unifi.update_frequency"},
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
	t.Setenv("UNIFI_PASSWORD", "secret")
	yaml := `unifi:
  enabled: true
  url: https://10.0.24.1
  username: admin
  password: ${UNIFI_PASSWORD}
  group_name: My_Block
  max_items: 500
  update_frequency: 10m
  insecure_skip_verify: false
` + minimalConfigYAML
	c, err := NewConfig(strings.NewReader(yaml))
	require.NoError(t, err)
	require.True(t, c.Unifi.Enabled)
	require.Equal(t, "https://10.0.24.1", c.Unifi.URL)
	require.Equal(t, "My_Block", c.Unifi.GroupName)
	require.Equal(t, 500, c.Unifi.MaxItems)
	require.Equal(t, 10*time.Minute, c.Unifi.UpdateFrequency)
	require.False(t, c.Unifi.InsecureSkipVerify)
	require.Equal(t, "secret", c.Unifi.Password)
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
