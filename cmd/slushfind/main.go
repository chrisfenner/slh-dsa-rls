// Package main contains the entry logic for slushfind
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/chrisfenner/slh-dsa-rls/pkg/search"
	"github.com/chrisfenner/slh-dsa-rls/pkg/slhdsa"
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
	targetSecurityLevel          = flag.Int("target_security_level", 128, "target security (in bits)")
	overuseSecurityLevel         = flag.Int("overuse_security_level", 112, "security level to calculate overuse")
	minSignatureCount            = flag.Float64("min_sig_count", 20.0, "log_2 of the minimum number of signatures at the required security level")
	minOveruseSignatureCount     = flag.Float64("min_sig_count_at_overuse", 0, "log_2 of the minimum number of signatures at the required security level")
	maxSignatureSize             = flag.Int("max_sig_size", 4000, "maximum signature size (in bytes)")
	minSignatureHashes           = flag.Int64("min_sig_hashes", 0, "minimum number of hashes to compute a signature")
	maxSignatureHashes           = flag.Int64("max_sig_hashes", 2000000000, "maximum number of hashes to compute a signature")
	maxCachedSignatureHashes     = flag.Int64("max_cached_sig_hashes", 2000000000, "maximum number of hashes to compute a signature")
	compareCachedSignatureHashes = flag.Bool("compare_cached_sig_hashes", false, "when true, signature hashes are compared based on the cached cost instead of the uncached")
	maxVerifyHashes              = flag.Int64("max_verify_hashes", 2000, "maximum number of hashes to verify a signature")
	sigSizeWeight                = flag.Float64("eval_sig_size", 0.5, "how much to consider signature size in the evaluation function")
	sigCostWeight                = flag.Float64("eval_sig_hashes", 0.0, "how much to consider signature cost in hashes in the evaluation function")
	verifyCostWeight             = flag.Float64("eval_verify_hashes", 0.5, "how much to consider verification cost in the evaluation function")
	tableFormat                  = flag.String("table_format", "console", "style for the output, one of ('console', 'markdown', 'csv')")
	namePrefix                   = flag.String("name_prefix", "", "prefix to use for parameter set ID")
)

func makeCompareFunc(cached bool) func(a, b *slhdsa.ParameterSet) bool {
	return func(a, b *slhdsa.ParameterSet) bool {
		var aCost, bCost float64
		if *sigSizeWeight != 0 {
			aCost += *sigSizeWeight * math.Log(float64(a.SignatureSize()))
			bCost += *sigSizeWeight * math.Log(float64(b.SignatureSize()))
		}
		if *sigCostWeight != 0 {
			var aSigHashes, bSigHashes int64
			if cached {
				aSigHashes = a.CachedSignatureHashes()
				bSigHashes = b.CachedSignatureHashes()
			} else {
				aSigHashes = a.SignatureHashes()
				bSigHashes = b.SignatureHashes()
			}
			aCost += *sigCostWeight * math.Log(float64(aSigHashes))
			bCost += *sigCostWeight * math.Log(float64(bSigHashes))
		}
		if *verifyCostWeight != 0 {
			aCost += *verifyCostWeight * math.Log(float64(a.VerifyHashes()))
			bCost += *verifyCostWeight * math.Log(float64(b.VerifyHashes()))
		}
		return aCost < bCost
	}
}

func prettyBigNumber(number int64) string {
	switch {
	case number > 1e9:
		return fmt.Sprintf("%.3gB", float64(number)/1000000000.0)
	case number > 1e6:
		return fmt.Sprintf("%.3gM", float64(number)/1000000.0)
	case number > 1e3:
		return fmt.Sprintf("%.3gK", float64(number)/1000.0)
	}
	return fmt.Sprintf("%d", number)
}

func main() {
	flag.Parse()
	extraArgs := flag.Args()
	if len(extraArgs) != 0 {
		fmt.Fprintf(os.Stderr, "unrecognized arguments: %v", strings.Join(extraArgs, ", "))
		os.Exit(1)
	}

	t := table.NewWriter()
	var render func() string
	switch strings.ToLower(*tableFormat) {
	case "console":
		render = t.Render
	case "markdown":
		render = t.RenderMarkdown
	case "csv":
		render = t.RenderCSV
	default:
		fmt.Fprintf(os.Stderr, "unrecognized table format: %v", *tableFormat)
		os.Exit(1)
	}

	searchParams := search.Parameters{
		TargetSecurityLevel:   *targetSecurityLevel,
		MinSignatures:         math.Exp2(*minSignatureCount),
		OveruseSecurityLevel:  *overuseSecurityLevel,
		MinOveruseSignatures:  math.Exp2(*minOveruseSignatureCount),
		HPrime:                intsBetween(1, 30),
		D:                     intsBetween(1, 30),
		LgW:                   intsBetween(1, 8),
		K:                     intsBetween(1, 30),
		T:                     intsBetween(1, 30),
		SignatureSize:         func(sz int) bool { return sz <= *maxSignatureSize },
		SignatureHashes:       func(hashes int64) bool { return *minSignatureHashes < hashes && hashes < *maxSignatureHashes },
		CachedSignatureHashes: func(hashes int64) bool { return hashes < *maxCachedSignatureHashes },
		VerifyHashes:          func(hashes int64) bool { return hashes < *maxVerifyHashes },
		Compare:               makeCompareFunc(*compareCachedSignatureHashes),
		CandidateCount:        20,
	}

	results := search.Search(&searchParams)

	t.AppendHeader(table.Row{
		"id",
		"h",
		"d",
		"h'",
		"a",
		"k",
		"w",
		"m",
		"sig bytes",
		"sign time",
		"sign cached",
		"verify time",
		fmt.Sprintf("sigs at %v", *overuseSecurityLevel),
	})

	for i, result := range results {
		id := fmt.Sprintf("%s%d", *namePrefix, i+1)
		t.AppendRow(table.Row{
			id,                       // "i",
			result.HypertreeHeight(), // "h",
			result.D,                 // "d",
			result.HPrime,            // "h'",
			result.T,                 // "a",
			result.K,                 // "k",
			result.LgW,               // "lg_w",
			result.M(),               // "m",
			result.SignatureSize(),   // "sig bytes",
			prettyBigNumber(result.SignatureHashes()),       // "sign time",
			prettyBigNumber(result.CachedSignatureHashes()), // "sign cached",
			result.VerifyHashes(),                           // "verify time",
			result.SignaturesAtLevel(*overuseSecurityLevel), // "sigs at {fallbackSecurityLevel}",
		})
	}

	t.SetStyle(table.StyleColoredDark)
	t.Style().Title.Align = text.AlignCenter
	title := fmt.Sprintf("Target security level %d, 2^%.0f signatures", *targetSecurityLevel, *minSignatureCount)
	if *minOveruseSignatureCount > 0 {
		title += fmt.Sprintf(" (level %d @ 2^%.0f signatures)", *overuseSecurityLevel, *minOveruseSignatureCount)
	}
	t.SetTitle(title)
	fmt.Println(render())
}
