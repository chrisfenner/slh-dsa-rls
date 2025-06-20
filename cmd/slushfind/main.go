// Package main contains the entry logic for slushfind
package main

import (
	"fmt"
	"math"

	"github.com/chrisfenner/slushfind/pkg/search"
	"github.com/chrisfenner/slushfind/pkg/slhdsa"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
)

func main() {
	searchParams := search.Parameters{
		TargetSecurityLevel: 128,
		MinSignatures:       math.Exp2(20),
		HPrime:              []int{4, 5},
		D:                   []int{4, 5, 6, 7, 8},
		LgW:                 []int{4},
		K:                   []int{15, 16, 17, 18, 19, 20, 21, 22, 23},
		T:                   []int{7, 8, 9},
		SignatureSize:       func(sz int) bool { return sz <= 10000 },
		SignatureHashes:     func(hashes int64) bool { return hashes < 100000 },
		VerifyHashes:        func(hashes int64) bool { return hashes < 3000 },
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
		"sigs at 112",
	})

	for i, result := range results {
		t.AppendRow(table.Row{
			i,                             // "i",
			result.HypertreeHeight(),      // "h",
			result.D,                      // "d",
			result.HPrime,                 // "h'",
			result.T,                      // "a",
			result.K,                      // "k",
			result.LgW,                    // "lg_w",
			result.M(),                    // "m",
			result.SignatureSize(),        // "sig bytes",
			result.SignatureHashes(),      // "sign time",
			result.VerifyHashes(),         // "verify time",
			result.SignaturesAtLevel(112), // "sigs at 112",
		})
	}

	t.SetStyle(table.StyleColoredDark)
	t.Style().Title.Align = text.AlignCenter
	t.SetTitle("Parameters for target security level 128, 2^20 signatures")
	fmt.Println(t.Render())
}
