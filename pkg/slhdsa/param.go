// Package slhdsa contains SLH-DSA related code.
package slhdsa

import (
	"math"
)

// ParameterSet contains all the values required to instantiate SLH-DSA.
type ParameterSet struct {
	// The target security level in bits of the signature (e.g., 128 for Level 1)
	TargetSecurityLevel int
	// The overuse security level in bits of the signature (e.g., 112 bits)
	OveruseSecurityLevel int
	// The height of each XMSS key
	HPrime int
	// The number of layers of one-time signatures and Merkle trees within the hypertree
	D int
	// The log_2 of the Winternitz parameter for the one-time signatures
	LgW int
	// The number of sets within a FORS
	K int
	// The 2^a = t private values within each FORS set
	T int

	// Cached values
	securityLevelSignatureCount             *float64
	securityLevel                           *float64
	checkSecurityLevelSignatureCount        *float64
	checkedSecurityLevel                    *bool
	checkOveruseSecurityLevelSignatureCount *float64
	checkedOveruseSecurityLevel             *bool
}

// The height of each XMSS key
func (p *ParameterSet) HypertreeHeight() int {
	return p.HPrime * p.D
}

// ceil returns the ceiling of the given division of two integers, as an integer
func ceil(num, denom int) int {
	return (num + denom - 1) / denom
}

// The length in bytes of the message digest
func (p *ParameterSet) M() int {
	return ceil(p.HypertreeHeight()-p.HPrime, 8) + ceil(p.HPrime, 8) + ceil(p.K*p.T, 8)
}

func (p *ParameterSet) SecurityLevel(m float64) float64 {
	if p.securityLevelSignatureCount != nil && *p.securityLevelSignatureCount == m {
		return *p.securityLevel
	}

	// Compute & cache
	p.securityLevelSignatureCount = &m
	result := p.computeSecurityLevel(m)
	p.securityLevel = &result
	return result
}

// Computes the exact security level of the parameter set for 2^m signatures
// This is a Go translation of Scott Fluhrer's algorithm `compute_sec_level` from
// https://github.com/sfluhrer/sphincs-param-set-search/blob/main/gamma.c
func (p *ParameterSet) computeSecurityLevel(m float64) float64 {
	// Lambda is the expected number of signatures per hypertree leaf at the specified number of signatures.
	lambda := 0.0
	if m > float64(p.HypertreeHeight()) {
		lambda = math.Exp2(m - float64(p.HypertreeHeight()))
	} else {
		lambda = math.Pow(0.5, float64(p.HypertreeHeight())-m)
	}
	log_lambda := m - float64(p.HypertreeHeight())

	// This is the probability that a probe does not hit a specific valid signature within a specific FORS tree
	prob_not_get_single_hit := 1.0 - math.Pow(0.5, float64(p.T))

	// This is the probability that no probes hit a specific valid signature in a specific FORS tree
	// after g signatures have been generated from this FORS.
	// This is updated as g is iterated.
	prob_not_get_g_hit := 1.0

	// a == lambda^g
	log_a := 0.0

	// the running sum
	log_sum := 0.0

	for g := 1; ; g++ {
		// Update the variables that depend on g
		log_a += float64(log_lambda)
		log_a -= math.Log2(float64(g))
		prob_not_get_g_hit *= prob_not_get_single_hit

		// a is the probability that there will be precisely g valid signatures
		// for this FORS (except for the constant e^{-\lambda} term; we'll
		// account for that at the end)

		// Compute b which is probability that a single forgery query will lie
		// entirely in revealed FORS leaves (and thus will allow a signature
		// of that forgery), assuming we have precisely g valid signatures for
		// this FORS
		log_b := 0.0
		if prob_not_get_g_hit < 0.00001 {
			// If prob_not_get_g_hit is sufficiently small, the subtraction
			// will lose significant bits (or just result in 1)
			// In this regime, the quadratic approximation, that is, the first
			// two terms in the Taylor expansion, gives us a more accurate value
			log_b = float64(-p.K) * (prob_not_get_g_hit/math.Log(2.0) +
				prob_not_get_g_hit*prob_not_get_g_hit/(2*math.Log(2.0)))
		} else {
			log_b = float64(p.K) * math.Log2(1-prob_not_get_g_hit)
		}

		// Hence, the probability that this iteration adds to the sum is
		// a*b, and since we're dealing with logs, log(ab) = log(a) + log(b)
		if g == 1 {
			// For the first iteration, the running sum is the first output
			log_sum = log_a + log_b
		} else {
			// For latter iterations, add log(ab) to the running sum
			log_sum = math.Log2(math.Exp2(log_sum) + math.Exp2(log_a+log_b))
		}

		// If the additional terms we're seeing is less than 2^{-20} of the
		// sum, any further terms won't change the answer much - we might as
		// well stop.  We test against log_a, as that is strictly decreasing
		// and bounds the probability (as log_b < 0)
		if g >= 10 && log_sum > 20+log_a {
			break
		}
	}

	return lambda*math.Log2(math.E) - log_sum
}

func (p *ParameterSet) CheckSecurityLevel(m float64) bool {
	if p.checkSecurityLevelSignatureCount != nil && *p.checkSecurityLevelSignatureCount == m {
		return *p.checkedSecurityLevel
	}

	// Compute & cache
	p.checkSecurityLevelSignatureCount = &m
	result := p.checkSecurityLevel(m)
	p.checkedSecurityLevel = &result
	return result
}

func (p *ParameterSet) CheckOveruseSecurityLevel(m float64) bool {
	if p.checkOveruseSecurityLevelSignatureCount != nil && *p.checkOveruseSecurityLevelSignatureCount == m {
		return *p.checkedOveruseSecurityLevel
	}

	// Compute & cache
	p.checkOveruseSecurityLevelSignatureCount = &m
	result := p.checkOveruseSecurityLevel(m)
	p.checkedOveruseSecurityLevel = &result
	return result
}

// Checks if the parameter set meets its target security level for 2^m signatures
func (p *ParameterSet) checkSecurityLevel(m float64) bool {
	return p.computeSecurityLevel(m) >= float64(p.TargetSecurityLevel)
}

// Checks if the parameter set meets its target overuse security level for 2^m signatures
func (p *ParameterSet) checkOveruseSecurityLevel(m float64) bool {
	return p.computeSecurityLevel(m) >= float64(p.OveruseSecurityLevel)
}

// The log_2 of the number of signatures that can be performed while retaining the security level
// This is a Go translation of Scott Fluhrer's algorithm `compute_sigs_at_sec_level` from
// https://github.com/sfluhrer/sphincs-param-set-search/blob/main/gamma.c
func (p *ParameterSet) SignaturesAtLevel(target int) float64 {
	// Scan for the number of signatures at a gross level (by integers)
	lower := 0
	for p.computeSecurityLevel(float64(lower+1)) > float64(target) {
		lower++
	}
	// Now scan by hundreds
	fract := 0
	for p.computeSecurityLevel(float64(lower)+float64(fract)/100.0+0.005) > float64(target) {
		fract++
	}
	return float64(lower) + (float64(fract) / 100.0)
}

// Returns the number of Winternitz digits used
func (p *ParameterSet) WinternitzDigits() int {
	hash_d := ceil(p.TargetSecurityLevel, p.LgW)
	w := 1 << p.LgW
	max_sum := (w - 1) * hash_d
	checksum_d := 1
	for prod := w; prod < max_sum; prod *= w {
		checksum_d++
	}
	return hash_d + checksum_d
}

// The size in bytes of each signature
func (p *ParameterSet) SignatureSize() int {
	hash_size := (p.TargetSecurityLevel + 7) / 8

	return hash_size * (1 + p.K*(p.T+1) + p.D*(p.WinternitzDigits()+p.HPrime))
}

// The number of hash operations required to produce a signature
func (p *ParameterSet) SignatureHashes() int64 {
	cost_ots := 1 + int64(p.WinternitzDigits())*(1<<p.LgW)
	cost_hypertree := int64(p.D) * ((cost_ots+1)*(1<<p.HPrime) - 1)
	cost_fors_tree := int64(3)*(1<<int64(p.T)) - 1
	return 3 + cost_hypertree + int64(p.K)*cost_fors_tree
}

// The number of hash operations required to produce a signature if the hypertree is cached.
func (p *ParameterSet) CachedSignatureHashes() int64 {
	cost_fors_tree := int64(3)*(1<<int64(p.T)) - 1
	return 3 + int64(p.K)*cost_fors_tree
}

// The number of hash operations required to verify a signature
func (p *ParameterSet) VerifyHashes() int64 {
	return int64(1) + int64(p.K)*(int64(p.T)+1) + 1 + (int64(p.D) * (int64(p.WinternitzDigits())*(1<<int64(p.LgW))/2 + 1 + int64(p.HPrime)))
}
