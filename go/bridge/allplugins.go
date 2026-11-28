//go:build allplugins

// Every in-tree CoreDNS plugin, any of which `cargo xtask build-bridge` can
// put in the bridge. Never part of a normal build: the tag keeps this
// module's go.mod and go.sum covering their dependencies (`go mod tidy`
// ignores build tags), so the dependency versions the bridge selects for
// them are pinned here and `govulncheck -tags allplugins ./...` checks
// them (.github/workflows/deps.yml).

package main

import _ "github.com/coredns/coredns/core/plugin"
