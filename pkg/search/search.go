// Package search provides an algorithm for searching the SLH-DSA parameter space.
package search

import (
	"iter"
	"math"
	"slices"
	"sort"
	"sync"

	"github.com/chrisfenner/slh-dsa-rls/pkg/slhdsa"
)

// Parameters defines the parameters of a search space.
type Parameters struct {
	// The target security level for this search
	TargetSecurityLevel int
	// The minimum number of signatures this parameter set must be able to support at full security level
	MinSignatures float64
	// The overuse security level for this search (ignored if <= 0 or if MinOveruseSignatures <= 0)
	OveruseSecurityLevel int
	// The minimum number of signatures this parameter set must be able to support at overuse security level (ignored if <= 0 or if OveruseSecurityLevel <= 0)
	MinOveruseSignatures float64
	// Acceptable XMSS key heights
	HPrime []int
	// Acceptable number of layers of one-time signatures and Merkle trees within the hypertree
	D []int
	// Acceptable values for log_2(w), the Winternitz parameter for the one-time signatures
	LgW []int
	// Acceptable values for K, the number of sets within a FORS
	K []int
	// Acceptable values for 2^a = t, the number of private values within each FORS set
	T []int

	// A function that determines whether a given signature size is acceptable
	SignatureSize func(int) bool
	// A function that determines whether a given signature cost is acceptable
	SignatureHashes func(int64) bool
	// A function that determines whether a given signature cost is acceptable (when 1 layer of the hypertree is cached)
	CachedSignatureHashes func(int64) bool
	// A function that determines whether a given verification cost is acceptable
	VerifyHashes func(int64) bool
	// A function that compares two parameter sets, returns true if p1 is "better" than p2
	Compare func(p1, p2 *slhdsa.ParameterSet) bool
	// Max number of candidate parameter sets to print
	CandidateCount int
}

func (p *Parameters) candidates() iter.Seq[*slhdsa.ParameterSet] {
	return func(yield func(*slhdsa.ParameterSet) bool) {
		for _, hPrime := range p.HPrime {
			for _, d := range p.D {
				for _, lgW := range p.LgW {
					for _, k := range p.K {
						for _, t := range p.T {
							candidate := slhdsa.ParameterSet{
								TargetSecurityLevel:  p.TargetSecurityLevel,
								OveruseSecurityLevel: p.OveruseSecurityLevel,
								HPrime:               hPrime,
								D:                    d,
								LgW:                  lgW,
								K:                    k,
								T:                    t,
							}
							// Yield the candidate
							if !yield(&candidate) {
								return
							}
						}
					}
				}
			}
		}
	}
}

// Search performs the parameter set space search and returns the top `CandidateCount` candidates.
func Search(params *Parameters) []slhdsa.ParameterSet {
	result := make([]slhdsa.ParameterSet, 0, params.CandidateCount+1)
	candidateQueue := make(chan *slhdsa.ParameterSet)
	var wg1, wg2 sync.WaitGroup

	// Create a goroutine that just reads candidates out of the queue and inserts them into the result
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for {
			candidate, ok := <-candidateQueue
			if !ok {
				return
			}

			// Trivial case: we have no candidates yet.
			if len(result) == 0 {
				result = append(result, *candidate)
				continue
			}

			// We already have some candidates. Insert this one and trim off the last one.
			i := sort.Search(len(result), func(i int) bool { return params.Compare(candidate, &result[i]) })
			result = slices.Insert(result, i, *candidate)
			if len(result) > params.CandidateCount {
				result = result[:params.CandidateCount]
			}
		}
	}()

	// Search the entire acceptable solution space, adding candidates to the queue
	for candidate := range params.candidates() {
		wg2.Add(1)
		go func() {
			defer wg2.Done()

			// Check that the signature size is acceptable
			if !params.SignatureSize(candidate.SignatureSize()) {
				return
			}

			// Check that the signature work is acceptable
			if !params.SignatureHashes(candidate.SignatureHashes()) {
				return
			}
			if !params.CachedSignatureHashes(candidate.CachedSignatureHashes()) {
				return
			}

			// Check that the verify work is acceptable
			if !params.VerifyHashes(candidate.VerifyHashes()) {
				return
			}

			// Check that the security level is acceptable
			if !candidate.CheckSecurityLevel(math.Log2(params.MinSignatures)) {
				return
			}

			// Check overuse security (if applicable)
			if params.OveruseSecurityLevel > 0 && params.MinOveruseSignatures > 0 {
				if !candidate.CheckOveruseSecurityLevel(math.Log2(params.MinOveruseSignatures)) {
					return
				}
			}

			// Candidate is acceptable; enqueue it
			candidateQueue <- candidate
		}()
	}
	wg2.Wait()
	close(candidateQueue)
	wg1.Wait()

	return result
}
