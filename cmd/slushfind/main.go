// Package main contains the entry logic for slushfind
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/chrisfenner/slushfind/pkg/search"
	"github.com/chrisfenner/slushfind/pkg/slhdsa"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
)

func intsBetween(start, end int) []int {
	result := make([]int, end-start+1)
	for i := start; i <= end; i++ {
		result[i-start] = i
	}
	return result
}

var (
	targetSecurityLevel   = flag.Int("target_security_level", 128, "target security (in bits)")
	fallbackSecurityLevel = flag.Int("fallback_security_level", 112, "security level to calculate overuse")
	minSignatureCount     = flag.Float64("min_signature_count", 20.0, "log_2 of the minimum number of signatures at the required security level")
	maxSignatureSize      = flag.Int("max_sig_size", 4000, "maximum signature size (in bytes)")
	minSignatureHashes    = flag.Int64("min_sig_hashes", 0, "minimum number of hashes to compute a signature")
	maxSignatureHashes    = flag.Int64("max_sig_hashes", 10000000, "maximum number of hashes to compute a signature")
	maxVerifyHashes       = flag.Int64("max_verify_hashes", 2000, "maximum number of hashes to verify a signature")
)

func main() {
	flag.Parse()
	extraArgs := flag.Args()
	if len(extraArgs) != 0 {
		fmt.Fprintf(os.Stderr, "unrecognized arguments: %v", strings.Join(extraArgs, ", "))
	}

	searchParams := search.Parameters{
		TargetSecurityLevel: *targetSecurityLevel,
		MinSignatures:       math.Exp2(*minSignatureCount),
		HPrime:              intsBetween(1, 30),
		D:                   intsBetween(1, 30),
		LgW:                 intsBetween(1, 4),
		K:                   intsBetween(1, 30),
		T:                   intsBetween(1, 30),
		SignatureSize:       func(sz int) bool { return sz <= *maxSignatureSize },
		SignatureHashes:     func(hashes int64) bool { return *minSignatureHashes < hashes && hashes < *maxSignatureHashes },
		VerifyHashes:        func(hashes int64) bool { return hashes < *maxVerifyHashes },
		Compare:             func(a, b *slhdsa.ParameterSet) bool { return a.SignatureSize() < b.SignatureSize() },
		CandidateCount:      20,
	}

	results := search.Search(&searchParams)

	t := table.NewWriter()
	t.AppendHeader(table.Row{
		"i",
		"h",
		"d",
		"h'",
		"a",
		"k",
		"lg_w",
		"m",
		"sig bytes",
		"sign time",
		"verify time",
		fmt.Sprintf("sigs at %v", *fallbackSecurityLevel),
	})

	for i, result := range results {
		t.AppendRow(table.Row{
			i,                        // "i",
			result.HypertreeHeight(), // "h",
			result.D,                 // "d",
			result.HPrime,            // "h'",
			result.T,                 // "a",
			result.K,                 // "k",
			result.LgW,               // "lg_w",
			result.M(),               // "m",
			result.SignatureSize(),   // "sig bytes",
			result.SignatureHashes(), // "sign time",
			result.VerifyHashes(),    // "verify time",
			result.SignaturesAtLevel(*fallbackSecurityLevel), // "sigs at 112",
		})
	}

	t.SetStyle(table.StyleColoredDark)
	t.Style().Title.Align = text.AlignCenter
	t.SetTitle(fmt.Sprintf("Target security level %d, 2^%.1f signatures", *targetSecurityLevel, *minSignatureCount))
	fmt.Println(t.Render())
}
