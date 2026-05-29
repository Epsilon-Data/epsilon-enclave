// Command tdquote mints an Intel TDX quote that binds a caller-supplied
// 64-byte REPORTDATA, using the same go-tdx-guest path validated on the
// target GCP C3 confidential VM.
//
// It reads the REPORTDATA from stdin -- either 64 raw bytes or 128 hex
// characters -- and writes the raw TD quote to stdout. The Epsilon TDX
// enclave agent shells out to this binary, passing REPORTDATA =
// SHA-512(canonical per-execution proof JSON), so the hardware-signed quote
// commits to exactly the same fields the Nitro backend binds into user_data.
//
// Build:  go mod tidy && go build -o tdquote .
// Usage:  printf '%s' "<128-hex>" | ./tdquote > quote.bin
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-tdx-guest/client"
)

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read stdin: %v", err)
	}

	var reportData [64]byte
	switch s := strings.TrimSpace(string(raw)); {
	case len(raw) == 64:
		copy(reportData[:], raw)
	case len(s) == 128:
		b, err := hex.DecodeString(s)
		if err != nil {
			fail("hex decode REPORTDATA: %v", err)
		}
		copy(reportData[:], b)
	default:
		fail("REPORTDATA must be 64 raw bytes or 128 hex chars; got %d bytes / %d trimmed chars", len(raw), len(s))
	}

	provider, err := client.GetQuoteProvider()
	if err != nil {
		fail("no TDX quote provider (configfs-tsm / /dev/tdx_guest unavailable): %v", err)
	}
	quote, err := client.GetRawQuote(provider, reportData)
	if err != nil {
		fail("get raw quote (host QGS unreachable?): %v", err)
	}
	if _, err := os.Stdout.Write(quote); err != nil {
		fail("write quote to stdout: %v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tdquote: "+format+"\n", args...)
	os.Exit(1)
}
