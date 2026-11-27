// Package rank scores CrowdSec decisions so the most severe ones win the
// limited slots in a Cloudflare IP list.
package rank

import (
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
)

type compiledPattern struct {
	name    string
	pattern *regexp.Regexp
	score   int
}

// Ranker assigns a severity score to decisions and orders them by it.
type Ranker struct {
	cfg      cfg.RankingConfig
	patterns []compiledPattern
}

// New compiles the configured scenario patterns.
func New(config cfg.RankingConfig) (*Ranker, error) {
	r := &Ranker{cfg: config}
	for _, p := range config.Patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("ranking pattern %s: %w", p.Name, err)
		}
		r.patterns = append(r.patterns, compiledPattern{name: p.Name, pattern: re, score: p.Score})
	}
	return r, nil
}

// StartTime reconstructs when a decision started from its expiry and duration.
func (r *Ranker) StartTime(d *models.Decision) time.Time {
	if d == nil || d.Until == "" {
		return time.Time{}
	}
	until, err := time.Parse(time.RFC3339, d.Until)
	if err != nil {
		return time.Time{}
	}
	if d.Duration == nil {
		return until
	}
	duration, err := time.ParseDuration(*d.Duration)
	if err != nil {
		return until
	}
	return until.Add(-duration)
}

// Score returns the severity score of a decision. Higher is more relevant.
func (r *Ranker) Score(d *models.Decision, now time.Time) int {
	if d == nil {
		return 0
	}
	score := r.cfg.DefaultScore
	scenario := ""
	if d.Scenario != nil {
		scenario = *d.Scenario
	}
	for _, p := range r.patterns {
		if p.pattern.MatchString(scenario) {
			score = p.score
			break
		}
	}
	if d.Type != nil {
		score += r.cfg.TypeScores[*d.Type]
	}
	if d.Origin != nil {
		score += r.cfg.OriginScores[*d.Origin]
	}
	start := r.StartTime(d)
	if !start.IsZero() {
		hours := int(now.Sub(start).Hours())
		if hours > 0 {
			bonus := hours * r.cfg.DurationBonusPerHour
			if bonus > r.cfg.DurationBonusMax {
				bonus = r.cfg.DurationBonusMax
			}
			score += bonus
		}
	}
	return score
}

// better reports whether candidate should replace current for the same value.
func (r *Ranker) better(candidate, current *models.Decision, now time.Time) bool {
	cs, currentScore := r.Score(candidate, now), r.Score(current, now)
	if cs != currentScore {
		return cs > currentScore
	}
	if candidate.Type != nil && *candidate.Type == "ban" && (current.Type == nil || *current.Type != "ban") {
		return true
	}
	return r.StartTime(candidate).After(r.StartTime(current))
}

// Rank filters out simulated and expired decisions, deduplicates by value
// keeping the most severe copy, and sorts by severity, recency then value.
func (r *Ranker) Rank(decisions []*models.Decision, now time.Time) []*models.Decision {
	byValue := make(map[string]*models.Decision, len(decisions))
	for _, d := range decisions {
		if d == nil || d.Value == nil {
			continue
		}
		if d.Simulated != nil && *d.Simulated {
			continue
		}
		if d.Until != "" {
			until, err := time.Parse(time.RFC3339, d.Until)
			if err == nil && until.Before(now) {
				continue
			}
		}
		current, ok := byValue[*d.Value]
		if !ok || r.better(d, current, now) {
			byValue[*d.Value] = d
		}
	}

	ranked := make([]*models.Decision, 0, len(byValue))
	for _, d := range byValue {
		ranked = append(ranked, d)
	}
	sort.Slice(ranked, func(i, j int) bool {
		si, sj := r.Score(ranked[i], now), r.Score(ranked[j], now)
		if si != sj {
			return si > sj
		}
		startI, startJ := r.StartTime(ranked[i]), r.StartTime(ranked[j])
		if !startI.Equal(startJ) {
			return startI.After(startJ)
		}
		return *ranked[i].Value < *ranked[j].Value
	})
	return ranked
}
