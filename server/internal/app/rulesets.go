package app

import (
	"fmt"
	"log/slog"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/rulesetapi"
	"cyberguard/server/internal/rulesets"
)

// Construction of the ruleset service, shared by the api and worker binaries.
//
// Both need it: the API serves the published snapshot, the worker is what
// publishes it. If only one had it, every publication would race the read.

// NewRulesetService builds the ruleset service from configuration.
//
// It returns a disabled service when rulesets are switched off, so callers do
// not each have to branch on the setting.
func NewRulesetService(
	cfg config.Config,
	store *mongostore.Store,
	logger *slog.Logger,
) (*rulesetapi.Service, error) {
	if !cfg.RulesetEnabled {
		logger.Warn("protection ruleset generation is disabled (RULESET_ENABLED=false); " +
			"GET /api/v1/get-all will report 503")
		return nil, nil
	}

	if store == nil {
		return nil, fmt.Errorf("app: a MongoDB store is required for the ruleset service")
	}

	scope, err := rulesets.ParseScope(cfg.RULESET_MAX_SCOPE)
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}

	action := rulesets.ActionType(cfg.RULESET_ACTION)
	if !action.Valid() {
		return nil, fmt.Errorf("app: RULESET_ACTION %q is not block or redirect", cfg.RULESET_ACTION)
	}
	profile, err := rulesets.ParseResourceProfile(cfg.RULESET_RESOURCE_PROFILE)
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}

	policy := rulesets.Policy{
		MaxScope:               scope,
		MinCorroboration:       cfg.RULESET_MIN_CORROBORATION,
		MinCorroborationPrefix: cfg.RULESET_MIN_CORROBORATION_PREFIX,
		MinCorroborationDomain: cfg.RULESET_MIN_CORROBORATION_DOMAIN,
		MaxRules:               cfg.RULESET_MAX_RULES,
		MaxRegexRules:          cfg.RULESET_MAX_REGEX_RULES,
		MinPathSegments:        rulesets.DefaultPolicy().MinPathSegments,
		Action:                 action,
		RedirectPath:           cfg.RULESET_REDIRECT_PATH,
		ResourceProfile:        profile,
		Priority:               cfg.RULESET_PRIORITY,
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("app: ruleset policy: %w", err)
	}

	generator, err := rulesets.NewGenerator(policy, store.NewRulesetEvidence())
	if err != nil {
		return nil, fmt.Errorf("app: ruleset generator: %w", err)
	}

	logger.Info("protection ruleset configured",
		slog.String("max_scope", scope.String()),
		slog.Int("min_corroboration", policy.MinCorroboration),
		slog.Int("min_corroboration_prefix", policy.MinCorroborationPrefix),
		slog.Int("min_corroboration_domain", policy.MinCorroborationDomain),
		slog.Int("max_rules", policy.MaxRules),
		slog.Int("max_regex_rules", policy.MaxRegexRules),
		slog.String("action", policy.Action.String()),
		slog.String("resource_profile", string(policy.ResourceProfile)),
		slog.Int("priority", policy.Priority),
	)

	if policy.Action == rulesets.ActionRedirect {
		// Chrome refuses a DNR redirect whose target is not declared in
		// web_accessible_resources. That is a client obligation the backend
		// cannot check, so it is surfaced at startup rather than discovered as a
		// ruleset that silently never installs.
		logger.Warn("ruleset action is redirect; the client must declare the redirect page in "+
			"web_accessible_resources or Chrome will refuse to install the ruleset",
			slog.String("extension_path", policy.RedirectPath))
	}

	return rulesetapi.New(store, generator, nil), nil
}
