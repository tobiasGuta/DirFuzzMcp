// Package scope loads H1-Scope-Watcher JSON files from a directory and
// validates whether a target URL is bounty-eligible before a scan starts.
//
// JSON structure expected in each file:
//
//	[
//	  {"asset_type": "URL",      "asset_identifier": "api.example.com", "eligible_for_bounty": true},
//	  {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",   "eligible_for_bounty": true}
//	]
package scope

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Asset is one entry from an H1-Scope-Watcher scope file.
type Asset struct {
	AssetType         string `json:"asset_type"`
	AssetIdentifier   string `json:"asset_identifier"`
	EligibleForBounty bool   `json:"eligible_for_bounty"`
}

// LoadDir reads every *.json file inside dir, parses each one as []Asset, and
// returns the combined slice. Files that cannot be read or parsed are skipped
// with a warning printed to stderr — a single bad file will not abort the load.
// Returns an error only if dir itself cannot be listed.
func LoadDir(dir string) ([]Asset, error) {
	pattern := filepath.Join(dir, "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("scope: listing %q: %w", dir, err)
	}

	var all []Asset
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scope: skipping %s (read error): %v\n", p, err)
			continue
		}
		var batch []Asset
		if err := json.Unmarshal(data, &batch); err != nil {
			fmt.Fprintf(os.Stderr, "scope: skipping %s (parse error): %v\n", p, err)
			continue
		}
		all = append(all, batch...)
	}
	return all, nil
}

// IsAllowed returns true when target is covered by at least one bounty-eligible
// asset in assets.  The check is case-insensitive on hostnames.
//
// Matching rules:
//   - "URL"      asset: target host must equal the asset identifier host.
//   - "WILDCARD" asset: target host must be a strict subdomain of the wildcard
//     base (e.g. "dev.tile.com" matches "*.tile.com", but "tile.com" does not).
//
// Any asset whose eligible_for_bounty is false is silently skipped.
func IsAllowed(target string, assets []Asset) bool {
	targetHost := extractHost(target)
	if targetHost == "" {
		return false
	}

	for _, a := range assets {
		if !a.EligibleForBounty {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(a.AssetType)) {
		case "URL":
			if matchURL(targetHost, a.AssetIdentifier) {
				return true
			}
		case "WILDCARD":
			if matchWildcard(targetHost, a.AssetIdentifier) {
				return true
			}
		}
	}
	return false
}

// ── internal helpers ──────────────────────────────────────────────────────────

// extractHost returns the lowercase hostname (no port, no path) from a raw URL
// string or a bare hostname. Returns "" on any parse failure.
func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// url.Parse requires a scheme to recognise the host segment correctly.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// matchURL checks whether targetHost equals the host portion of identifier
// (after stripping any scheme/path from the identifier).
func matchURL(targetHost, identifier string) bool {
	idHost := extractHost(identifier)
	return idHost != "" && targetHost == idHost
}

// matchWildcard checks whether targetHost is a strict subdomain of the wildcard
// identifier.  The identifier may carry a scheme (e.g. "https://*.example.com")
// which is stripped before matching.
//
// Because url.Parse rejects hostnames starting with "*", we normalise the
// identifier with simple string operations rather than url.Parse.
func matchWildcard(targetHost, identifier string) bool {
	// Normalise: lowercase, strip scheme, strip path.
	clean := strings.ToLower(strings.TrimSpace(identifier))
	for _, scheme := range []string{"https://", "http://"} {
		clean = strings.TrimPrefix(clean, scheme)
	}
	if idx := strings.IndexByte(clean, '/'); idx != -1 {
		clean = clean[:idx]
	}
	// Strip port if present (wildcard assets rarely carry one, but be safe).
	if idx := strings.LastIndexByte(clean, ':'); idx != -1 {
		// Only strip if what follows looks like a port number.
		possiblePort := clean[idx+1:]
		if isNumeric(possiblePort) {
			clean = clean[:idx]
		}
	}

	if !strings.HasPrefix(clean, "*.") {
		return false
	}

	// baseDomain is everything after "*.".
	baseDomain := clean[2:]
	if baseDomain == "" {
		return false
	}

	// A strict subdomain must end with ".baseDomain" AND be longer than just
	// "baseDomain" itself — the apex is not covered by "*.apex".
	suffix := "." + baseDomain
	return strings.HasSuffix(targetHost, suffix)
}

// isNumeric returns true when s consists entirely of ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
