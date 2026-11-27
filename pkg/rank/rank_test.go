package rank

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
)

var testNow = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

func decision(scenario, typ, value string, simulated bool, until time.Time) *models.Decision {
	return &models.Decision{
		Scenario:  ptr.Of(scenario),
		Type:      ptr.Of(typ),
		Value:     ptr.Of(value),
		Scope:     ptr.Of("ip"),
		Origin:    ptr.Of("crowdsec"),
		Duration:  ptr.Of("4h"),
		Until:     until.Format(time.RFC3339),
		Simulated: ptr.Of(simulated),
	}
}

func testRanker(t *testing.T) *Ranker {
	t.Helper()
	r, err := New(cfg.RankingConfig{
		Patterns: []cfg.RankingPattern{
			{Name: "zero_day", Pattern: `(?i)(0day|zero.?day|cve-2026)`, Score: 100},
			{Name: "brute_force", Pattern: `(?i)(bf|brute)`, Score: 40},
			{Name: "scanning", Pattern: `(?i)scan`, Score: 10},
		},
		DefaultScore:         20,
		TypeScores:           map[string]int{"ban": 20, "captcha": 5},
		DurationBonusPerHour: 1,
		DurationBonusMax:     20,
		OriginScores:         map[string]int{"crowdsec": 10},
	})
	require.NoError(t, err)
	return r
}

func TestRankOrdersBySeverity(t *testing.T) {
	r := testRanker(t)
	until := testNow.Add(4 * time.Hour)
	got := r.Rank([]*models.Decision{
		decision("http-scan", "ban", "10.0.0.1", false, until),
		decision("ssh-bf", "ban", "10.0.0.2", false, until),
		decision("cve-2026-1234", "captcha", "10.0.0.3", false, until),
		decision("0day-exploit", "ban", "10.0.0.4", false, until),
	}, testNow)
	require.Len(t, got, 4)
	require.Equal(t, "10.0.0.4", *got[0].Value)
	require.Equal(t, "10.0.0.3", *got[1].Value)
	require.Equal(t, "10.0.0.2", *got[2].Value)
	require.Equal(t, "10.0.0.1", *got[3].Value)
}

func TestRankDedupKeepsHighestScore(t *testing.T) {
	r := testRanker(t)
	until := testNow.Add(4 * time.Hour)
	got := r.Rank([]*models.Decision{
		decision("ssh-bf", "ban", "1.2.3.4", false, until),
		decision("0day-exploit", "captcha", "1.2.3.4", false, until),
	}, testNow)
	require.Len(t, got, 1)
	require.Equal(t, "captcha", *got[0].Type)
}

func TestRankBanTieBreakIsSymmetric(t *testing.T) {
	r := testRanker(t)
	until := testNow.Add(4 * time.Hour)
	captchaUntil := until.Add(time.Hour)
	for _, decisions := range [][]*models.Decision{
		{decision("scan", "ban", "1.2.3.4", false, until), decision("scan", "captcha", "1.2.3.4", false, captchaUntil)},
		{decision("scan", "captcha", "1.2.3.4", false, captchaUntil), decision("scan", "ban", "1.2.3.4", false, until)},
	} {
		got := r.Rank(decisions, testNow)
		require.Len(t, got, 1)
		require.Equal(t, "ban", *got[0].Type)
	}
}

func TestRankDropsSimulatedAndExpired(t *testing.T) {
	r := testRanker(t)
	got := r.Rank([]*models.Decision{
		decision("0day-exploit", "ban", "1.2.3.4", true, testNow.Add(4*time.Hour)),
		decision("0day-exploit", "ban", "1.2.3.5", false, testNow.Add(-time.Hour)),
		decision("0day-exploit", "ban", "1.2.3.6", false, testNow.Add(4*time.Hour)),
	}, testNow)
	require.Len(t, got, 1)
	require.Equal(t, "1.2.3.6", *got[0].Value)
}

func TestStartTimeFromUntilMinusDuration(t *testing.T) {
	r := testRanker(t)
	d := decision("scan", "ban", "1.2.3.4", false, time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC))
	require.Equal(t, time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC), r.StartTime(d))
}
