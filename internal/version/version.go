// Package version records the SockHound build version.
package version

// Version is overridden at build time with -ldflags "-X .../internal/version.Version=...".
var Version = "0.1.0-dev"
