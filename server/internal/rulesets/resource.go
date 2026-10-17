package rulesets

import "fmt"

// Which request types a rule applies to.
//
// # Why this is a policy and not a constant
//
// Chrome treats `resourceTypes` as load-bearing rather than decorative. If a
// rule omits both `resourceTypes` and `excludedResourceTypes`, it matches every
// type **except `main_frame`** — so an omitted list silently stops a rule from
// blocking navigation, which for a phishing URL is the one thing it most needs to
// do.
//
// The list also decides what a rule breaks. A redirect replaces the response
// with a page from the extension, which is meaningful for a navigation and
// nonsense for a sub-resource: redirecting a `<script>` request to an HTML
// interstitials would break the page rather than protect it.
//
// # The two profiles this engine ships
//
//   - **navigation** — `main_frame` and `sub_frame`. What the user is about to
//     see. This is the only profile a redirect may use.
//   - **navigation_and_active** — the above plus everything that executes code,
//     reads a response or phones home: scripts, XHR, beacons, sockets.
//
// A block uses `navigation_and_active`: blocking the page alone would leave a
// malicious page's payload reachable if it were ever loaded in another context.
// A redirect uses `navigation`.
//
// # Overriding
//
// An operator may replace either profile through configuration, but the two
// invariants hold regardless and are enforced after any override:
//
//  1. a redirect rule may only name navigation resource types, and
//  2. a block rule's list must not be empty.
//
// A redirect aimed at a sub-resource would replace that sub-resource with an
// HTML page. That is not a stricter block; it is a broken page.

// ResourceProfile is a named set of resource types.
type ResourceProfile string

const (
	// ProfileNavigation covers only page loads.
	ProfileNavigation ResourceProfile = "navigation"

	// ProfileNavigationAndActive covers page loads plus the resource types
	// that can execute code, read data or signal out.
	ProfileNavigationAndActive ResourceProfile = "navigation_and_active"

	// ProfileAllSubresources covers every request type except a main-frame
	// navigation, mirroring Chrome's own default.
	ProfileAllSubresources ResourceProfile = "all_subresources"
)

// navigationTypes are the request types that render a document.
var navigationTypes = []ResourceType{
	ResourceMainFrame,
	ResourceSubFrame,
}

// activeTypes are the request types that execute, read or signal. They are the
// ones through which a malicious page does damage after it has loaded.
var activeTypes = []ResourceType{
	ResourceScript,
	ResourceXHR,
	ResourcePing,
	ResourceWebSocket,
	ResourceWebTransport,
}

// subresourceTypes are the remaining request types.
var subresourceTypes = []ResourceType{
	ResourceStylesheet,
	ResourceImage,
	ResourceFont,
	ResourceObject,
	ResourceMedia,
	ResourceWebBundle,
	ResourceCSPReport,
	ResourceOther,
}

// profiles maps a profile name to its types.
var profiles = map[ResourceProfile][]ResourceType{
	ProfileNavigation:          navigationTypes,
	ProfileNavigationAndActive: append(append([]ResourceType{}, navigationTypes...), activeTypes...),
	ProfileAllSubresources:     append(append([]ResourceType{}, navigationTypes...), append(append([]ResourceType{}, activeTypes...), subresourceTypes...)...),
}

// ResourceTypesFor returns the resource types a profile selects.
//
// The returned slice is a copy, so a caller cannot mutate the profile.
func ResourceTypesFor(p ResourceProfile) ([]ResourceType, error) {
	types, ok := profiles[p]
	if !ok {
		return nil, fmt.Errorf("rulesets: unknown resource profile %q", p)
	}

	out := make([]ResourceType, len(types))
	copy(out, types)
	return out, nil
}

// ParseResourceProfile converts a configured string into a profile.
func ParseResourceProfile(v string) (ResourceProfile, error) {
	p := ResourceProfile(v)
	if _, ok := profiles[p]; !ok {
		return "", fmt.Errorf("rulesets: unknown resource profile %q", v)
	}
	return p, nil
}

// KnownResourceProfiles lists the profile names, for configuration errors.
func KnownResourceProfiles() []string {
	out := make([]string, 0, len(profiles))
	for name := range profiles {
		out = append(out, string(name))
	}
	return out
}

// ResourceTypesForAction returns the resource types an action may use.
//
// It is the one place that couples action to resource type, so the redirect
// invariant is enforced on every rule built rather than being repeated at each
// call site.
func ResourceTypesForAction(action ActionType, p ResourceProfile) ([]ResourceType, error) {
	types, err := ResourceTypesFor(p)
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("%w: resource profile %q selects no resource types", ErrInvalidRule, p)
	}

	if action == ActionRedirect {
		// Filter down to navigation types rather than erroring: an operator who
		// points redirects at a broad profile gets the safe subset, not a
		// broken ruleset and not a silently broadened redirect.
		kept := make([]ResourceType, 0, len(navigationTypes))
		for _, t := range types {
			if t == ResourceMainFrame || t == ResourceSubFrame {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			return nil, fmt.Errorf(
				"%w: a redirect rule needs at least one navigation resource type, but profile %q selects none",
				ErrInvalidRule, p)
		}
		return kept, nil
	}

	return types, nil
}

// ResourceTypesToStrings renders resource types for the published JSON.
func ResourceTypesToStrings(types []ResourceType) []string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, string(t))
	}
	return out
}
