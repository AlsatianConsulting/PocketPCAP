// Package bind exists only to pin the tun2socks version that gomobile binds into
// PocketPCAP, and to hold the go.sum that makes that build reproducible.
//
// Nothing here is called. scripts/build-tun2socks-aar.sh runs
//
//	gomobile bind github.com/xjasonlyu/tun2socks/v2/engine
//
// from this directory, so the module graph recorded in go.mod and go.sum is what
// decides exactly which tun2socks, gVisor and wireguard-go sources end up compiled
// into app/libs/tun2socks.aar. tun2socks is GPL-3.0-only and is linked into the
// app's own process, which is why PocketPCAP is GPL-3.0-or-later; keeping the pin
// in the repository is what makes the written source offer in
// THIRD-PARTY-NOTICES.md answerable.
package bind

import _ "github.com/xjasonlyu/tun2socks/v2/engine"
