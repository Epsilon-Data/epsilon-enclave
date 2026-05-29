module epsilon/tdquote

go 1.21

// `go mod tidy` resolves github.com/google/go-tdx-guest to its latest tag
// (the same module validated by the probe on the GCP C3 TDX VM).
require github.com/google/go-tdx-guest v0.3.2
