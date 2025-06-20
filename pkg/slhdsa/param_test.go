package slhdsa

import (
	"math"
	"testing"
)

func closeEnough(a, b float64) bool {
	const threshold = 0.000001
	return math.Abs(a-b) <= threshold
}

func TestParameterSetCalculations(t *testing.T) {
	for _, tc := range []struct {
		Name                      string
		Params                    ParameterSet
		H                         int
		M                         int
		SignatureSize             int
		SignatureHashes           int64
		VerifyHashes              int64
		ReducedTarget             int
		SignaturesAtReducedTarget float64
	}{
		{
			Name: "A-1",
			Params: ParameterSet{
				TargetSecurityLevel: 128,
				HPrime:              5,
				D:                   4,
				T:                   8,
				K:                   23,
				LgW:                 4,
			},
			H:                         20,
			M:                         26,
			SignatureSize:             5888,
			SignatureHashes:           89576,
			VerifyHashes:              1353,
			ReducedTarget:             112,
			SignaturesAtReducedTarget: 21.69,
		},
		{
			Name: "A-12",
			Params: ParameterSet{
				TargetSecurityLevel: 128,
				HPrime:              4,
				D:                   8,
				T:                   9,
				K:                   15,
				LgW:                 4,
			},
			H:                         32,
			M:                         22,
			SignatureSize:             7408,
			SignatureHashes:           94956,
			VerifyHashes:              2432,
			ReducedTarget:             112,
			SignaturesAtReducedTarget: 30.79,
		},
		{
			Name: "AAA-1",
			Params: ParameterSet{
				TargetSecurityLevel: 128,
				HPrime:              15,
				D:                   2,
				T:                   24,
				K:                   5,
				LgW:                 8,
			},
			H:                         30,
			M:                         19,
			SignatureSize:             3072,
			SignatureHashes:           553779196, // https://eprint.iacr.org/2024/018.pdf has 553779200, might be a precision issue
			VerifyHashes:              4767,
			ReducedTarget:             112,
			SignaturesAtReducedTarget: 30.75,
		},
		{
			Name: "F-1",
			Params: ParameterSet{
				TargetSecurityLevel: 128,
				HPrime:              9,
				D:                   4,
				T:                   14,
				K:                   9,
				LgW:                 8,
			},
			H:                         36,
			M:                         22,
			SignatureSize:             3904,
			SignatureHashes:           9883638,
			VerifyHashes:              9393,
			ReducedTarget:             112,
			SignaturesAtReducedTarget: 35.92,
		},
		{
			Name: "N-7",
			Params: ParameterSet{
				TargetSecurityLevel: 192,
				HPrime:              8,
				D:                   3,
				T:                   12,
				K:                   18,
				LgW:                 4,
			},
			H:                         24,
			M:                         30,
			SignatureSize:             9888,
			SignatureHashes:           849390,
			VerifyHashes:              1487,
			ReducedTarget:             128,
			SignaturesAtReducedTarget: 28.51,
		},
		{
			Name: "W-1",
			Params: ParameterSet{
				TargetSecurityLevel: 192,
				HPrime:              5,
				D:                   10,
				T:                   12,
				K:                   20,
				LgW:                 6,
			},
			H:                         50,
			M:                         37,
			SignatureSize:             15624,
			SignatureHashes:           942693,
			VerifyHashes:              11202,
			ReducedTarget:             128,
			SignaturesAtReducedTarget: 55.34,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			if got, want := tc.Params.HypertreeHeight(), tc.H; got != want {
				t.Errorf("HPrime = %v, want %v", got, want)
			}
			if got, want := tc.Params.M(), tc.M; got != want {
				t.Errorf("M = %v, want %v", got, want)
			}
			if got, want := tc.Params.SignatureSize(), tc.SignatureSize; got != want {
				t.Errorf("SignatureSize = %v, want %v", got, want)
			}
			if got, want := tc.Params.SignatureHashes(), tc.SignatureHashes; got != want {
				t.Errorf("SignatureHashes = %v, want %v", got, want)
			}
			if got, want := tc.Params.VerifyHashes(), tc.VerifyHashes; got != want {
				t.Errorf("VerifyHashes = %v, want %v", got, want)
			}
			if got, want := tc.Params.SignaturesAtLevel(tc.ReducedTarget), tc.SignaturesAtReducedTarget; !closeEnough(got, want) {
				t.Errorf("SignaturesAt(%v) = %v, want %v", tc.ReducedTarget, got, want)
			}
		})
	}
}
