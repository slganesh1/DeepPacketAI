package uidist

import "embed"

// FS holds the embedded React production build.
// Run `npm run build` in deeppacketai-ui/ before `go build`.
//
//go:embed dist
var FS embed.FS
