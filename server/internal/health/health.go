// Package health provides dependency probes for the readiness endpoint.
//
// Liveness deliberately does not use this package. A MongoDB or Redis outage
// must not make an orchestrator restart every replica: that converts a
// dependency failure into a full outage. Only readiness consults dependencies.
//
// The Check interface is declared here, by the consumer, so the platform
// clients satisfy it implicitly. Nothing in platform/ needs to import this
// package to pass its health check.
package health

import (
	"context"
	"time"
)

// Check is a dependency that can be probed. It is satisfied structurally by
// *mongostore.Store and *redisqueue.Client, which both expose Ping.
type Check interface {
	Ping(ctx context.Context) error
}

// Named pairs a Check with the name reported in the readiness payload.
type Named struct {
	Name  string
	Check Check
}

// Report is the JSON shape of one probe result.
type Report struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Why  string `json:"why,omitempty"`
}

// Checker runs a fixed set of probes.
//
// Probes run sequentially, each bounded by the checker's timeout, so worst-case
// readiness latency is len(checks)*timeout. The check set is small and fixed,
// which makes a concurrent fan-out unnecessary complexity for a probe that is
// polled on the order of every ten seconds.
type Checker struct {
	checks  []Named
	timeout time.Duration
}

// NewChecker returns a Checker. A non-positive timeout falls back to 2s, so a
// misconfigured probe cannot hang the readiness endpoint indefinitely.
func NewChecker(timeout time.Duration, checks ...Named) *Checker {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Checker{checks: checks, timeout: timeout}
}

// Run probes every dependency and returns whether the service is ready along
// with one report per check.
//
// A non-nil error from a probe is reported, not propagated: readiness answers
// "can this process do useful work", and the useful information is which
// dependency is down, not a wrapped driver error.
//
// The why strings are deliberately generic. Driver and Redis error text can
// embed hosts, topology and credentials, and this payload is served
// unauthenticated.
func (c *Checker) Run(ctx context.Context) (ready bool, reports []Report) {
	ready = true
	reports = make([]Report, 0, len(c.checks))

	for _, chk := range c.checks {
		report := Report{Name: chk.Name, OK: true}

		pingCtx, cancel := context.WithTimeout(ctx, c.timeout)
		err := chk.Check.Ping(pingCtx)
		cancel()

		if err != nil {
			report.OK = false
			report.Why = "dependency unavailable"
			ready = false
		}
		reports = append(reports, report)
	}

	return ready, reports
}
