package rulesets

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// The Chrome Declarative Net Request surface CyberGuard emits.
//
// # What is emitted, and why only this
//
// The engine produces exactly two action types: `block` and `redirect`. It never
// emits `allow` or `allowAllRequests`, because those grant trust and this
// project only ever withholds it. It never emits `upgradeScheme` or
// `modifyHeaders`, because neither is a protection decision this product makes.
//
// # Action precedence, and why it is left to Chrome
//
// Chrome resolves a request to at most one action, ordering matching rules by
// `priority` and, at equal priority, by action: `allow` > `block` >
// `upgradeScheme` > `redirect`. Since this engine emits no `allow` rules, a
// `block` and a `redirect` rule that both match will resolve to `block`.
//
// That is the outcome this product wants, so the two are deliberately left at
// the same priority and the ordering is not overridden. Pinning a higher
// priority onto redirects would silently invert it and would make the published
// ruleset depend on a Chrome implementation detail.
//
// The documentation warns that ordering between rules of equal action and
// priority is explicitly not standardised between runs or browser versions.
// That is another reason to keep every emitted rule at one priority: there is
// no ordering to depend on.

// ActionType is a DNR rule action.
type ActionType string

const (
	// ActionBlock refuses the request outright.
	ActionBlock ActionType = "block"

	// ActionRedirect sends the request to a page inside the extension instead.
	ActionRedirect ActionType = "redirect"
)

// Valid reports whether a is an action this engine emits.
func (a ActionType) Valid() bool {
	switch a {
	case ActionBlock, ActionRedirect:
		return true
	default:
		return false
	}
}

// String returns the wire value.
func (a ActionType) String() string { return string(a) }

// Redirect describes how a redirect rule redirects.
//
// Exactly one of its fields is set by this engine. `extensionPath` is the only
// form used, and `url` is not merely unused but rejected, so that a rule can
// never send a user's browser to an address chosen by an assessment.
type Redirect struct {
	// ExtensionPath is a path relative to the extension's own directory. It
	// resolves to chrome-extension://<id>/locked.html.
	//
	// The extension is responsible for declaring the path in
	// `web_accessible_resources`; Chrome refuses a DNR redirect to a resource
	// that is not web accessible. That is a client obligation and is recorded
	// in the published contract, not something the backend can enforce.
	ExtensionPath string `json:"extensionPath,omitempty" bson:"extension_path,omitempty"`
}

// Action is what a matched rule does.
type Action struct {
	// Type is block or redirect.
	Type ActionType `json:"type" bson:"type"`

	// Redirect is present if and only if Type is redirect.
	Redirect *Redirect `json:"redirect,omitempty" bson:"redirect,omitempty"`
}

// ResourceType is a Chrome network request resource type.
//
// The full set is enumerated so that a rule naming anything outside it fails
// validation rather than being silently ignored by the browser.
type ResourceType string

const (
	ResourceMainFrame    ResourceType = "main_frame"
	ResourceSubFrame     ResourceType = "sub_frame"
	ResourceStylesheet   ResourceType = "stylesheet"
	ResourceScript       ResourceType = "script"
	ResourceImage        ResourceType = "image"
	ResourceFont         ResourceType = "font"
	ResourceObject       ResourceType = "object"
	ResourceXHR          ResourceType = "xmlhttprequest"
	ResourcePing         ResourceType = "ping"
	ResourceCSPReport    ResourceType = "csp_report"
	ResourceMedia        ResourceType = "media"
	ResourceWebSocket    ResourceType = "websocket"
	ResourceWebTransport ResourceType = "webtransport"
	ResourceWebBundle    ResourceType = "webbundle"
	ResourceOther        ResourceType = "other"
)

// knownResourceTypes is every value in Chrome's ResourceType enum.
//
// `csp_report`, `webtransport` and `webbundle` are included for completeness
// even though no shipped profile selects them: an operator overriding a
// profile must not be able to name a type the browser would reject.
var knownResourceTypes = map[ResourceType]bool{
	ResourceMainFrame:    true,
	ResourceSubFrame:     true,
	ResourceStylesheet:   true,
	ResourceScript:       true,
	ResourceImage:        true,
	ResourceFont:         true,
	ResourceObject:       true,
	ResourceXHR:          true,
	ResourcePing:         true,
	ResourceCSPReport:    true,
	ResourceMedia:        true,
	ResourceWebSocket:    true,
	ResourceWebTransport: true,
	ResourceWebBundle:    true,
	ResourceOther:        true,
}

// KnownResourceType reports whether r is in Chrome's enum.
func KnownResourceType(r ResourceType) bool { return knownResourceTypes[r] }

// Chrome's published limits, as documented for declarativeNetRequest.
//
// These are not tuning knobs. A snapshot that exceeds them is not "a large
// ruleset"; it is a ruleset Chrome refuses to install, which means every user
// silently loses all protection at once.
const (
	// MaxStaticRules is Chrome's guaranteed minimum for static rules across all
	// enabled rulesets. Session rules are far lower, and are the stricter
	// constraint this engine designs against.
	MaxStaticRules = 30000

	// MaxSessionRules is Chrome's hard session-scoped limit.
	MaxSessionRules = 5000

	// MaxDynamicSafeRules is the expanded quota for "safe" rules (block, allow,
	// upgradeScheme) from Chrome 121.
	MaxDynamicSafeRules = 30000

	// MaxRegexRules is Chrome's hard cap on rules using a regular expression,
	// per ruleset type. Redirect rules count as unsafe for quota, so this is
	// also the constraint on how much redirect the engine can ship.
	MaxRegexRules = 1000

	// MaxRegexRuleBytes is Chrome's per-rule compiled-regex size limit.
	MaxRegexRuleBytes = 2048

	// maxRuleID bounds the identifier.
	//
	// Chrome documents `id` only as a number that is >= 1 and unique; no upper
	// bound is stated. 2^31-1 is used as a conservative ceiling: it is the
	// largest value every JavaScript number represents exactly, so a client
	// cannot lose precision reading it.
	maxRuleID = 1 << 31

	// minRulePriority is Chrome's documented minimum for `priority`.
	minRulePriority = 1
)

// DefaultMaxRules is the engine's default snapshot size.
//
// It sits at Chrome's session-rules limit rather than the much larger dynamic
// quota, because a snapshot above 5000 cannot be installed by a client using
// session rules, and a ruleset that some clients cannot install is worse than a
// smaller one everybody can.
const DefaultMaxRules = MaxSessionRules

// DefaultMaxRegexRules is the engine's default cap on regex-scoped rules.
//
// It matches Chrome's documented limit exactly. Exceeding it would make the
// whole ruleset uninstallable, not just the offending rules.
const DefaultMaxRegexRules = MaxRegexRules

// ErrInvalidRule means a generated rule would be rejected by Chrome.
//
// The build treats this as fatal for the whole snapshot. Publishing a partial
// ruleset is worse than publishing none: the client would silently under-block
// while its operator believed coverage was complete.
var ErrInvalidRule = errors.New("rulesets: generated rule is invalid")

// ValidateAction checks an action against what this engine emits.
func (a Action) Validate() error {
	if !a.Type.Valid() {
		return fmt.Errorf("%w: action type %q is not emitted by this engine", ErrInvalidRule, a.Type)
	}

	switch a.Type {
	case ActionBlock:
		if a.Redirect != nil {
			// Chrome rejects a block action carrying a redirect. Emitting one
			// would mean the rule never installs, silently.
			return fmt.Errorf("%w: a block action must not carry a redirect", ErrInvalidRule)
		}
	case ActionRedirect:
		if a.Redirect == nil {
			return fmt.Errorf("%w: a redirect action needs a redirect", ErrInvalidRule)
		}
		if err := a.Redirect.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validate checks the redirect target.
//
// The rules here are stricter than Chrome's, because Chrome's own validation
// would accept anything that is syntactically a path. This engine will not emit
// a redirect that a misconfiguration could turn into an off-site navigation.
func (r Redirect) validate() error {
	p := r.ExtensionPath

	switch {
	case p == "":
		return fmt.Errorf("%w: redirect.extensionPath is empty", ErrInvalidRule)

	// Chrome requires the path to be relative to the extension directory, so it
	// must start with a single slash.
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%w: redirect.extensionPath %q must start with /", ErrInvalidRule, p)

	// "//host/path" is a protocol-relative URL, not an extension path. Chrome
	// would resolve it against the extension's own scheme, but the string is
	// ambiguous and nothing legitimate needs it.
	case strings.HasPrefix(p, "//"):
		return fmt.Errorf("%w: redirect.extensionPath %q looks like a protocol-relative URL", ErrInvalidRule, p)

	// A backslash is normalised to a slash by URL parsers in some contexts,
	// which turns "/\evil.com" into a cross-origin path.
	case strings.Contains(p, `\`):
		return fmt.Errorf("%w: redirect.extensionPath %q contains a backslash", ErrInvalidRule, p)

	// Traversal above the extension root.
	case strings.Contains(p, ".."):
		return fmt.Errorf("%w: redirect.extensionPath %q contains a parent reference", ErrInvalidRule, p)

	// A query or fragment is not a path, and one of them could carry data.
	case strings.ContainsAny(p, "?#"):
		return fmt.Errorf("%w: redirect.extensionPath %q must be a path with no query or fragment", ErrInvalidRule, p)

	case !utf8.ValidString(p):
		return fmt.Errorf("%w: redirect.extensionPath is not valid UTF-8", ErrInvalidRule)

	// Control characters, including a newline that could break out of the
	// JSON string it is embedded in.
	case hasControl(p):
		return fmt.Errorf("%w: redirect.extensionPath contains a control character", ErrInvalidRule)
	}

	// Chrome caps static rule file sizes; a path anywhere near that is a
	// configuration error, not a real target.
	if len(p) > 512 {
		return fmt.Errorf("%w: redirect.extensionPath is %d characters", ErrInvalidRule, len(p))
	}

	return nil
}

// hasControl reports whether s contains an ASCII control character.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
