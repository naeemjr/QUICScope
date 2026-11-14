//! A tiny deterministic generator (SplitMix64). The benchmark needs
//! reproducible traces, not statistical quality or secrecy.

const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GAMMA);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`. The slight modulo bias is irrelevant here.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0)");
        self.next_u64() % n
    }

    /// Uniform in `lo..hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo < hi, "empty range {lo}..{hi}");
        lo + self.below(hi - lo)
    }

    /// True with probability `per_mille / 1000`.
    pub fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < u64::from(per_mille)
    }
}

/// Derive an independent seed from a seed and an index.
pub fn mix(seed: u64, index: u64) -> u64 {
    SplitMix64::new(seed ^ index.wrapping_mul(GAMMA)).next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_vector() {
        // First outputs of SplitMix64 seeded with 0, from the reference C code.
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn same_seed_same_stream() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn range_and_below_stay_in_bounds() {
        let mut rng = SplitMix64::new(7);
        for _ in 0..500 {
            assert!(rng.below(3) < 3);
            let v = rng.range(10, 13);
            assert!((10..13).contains(&v));
        }
    }

    #[test]
    fn chance_extremes_are_certain() {
        let mut rng = SplitMix64::new(9);
        assert!((0..200).all(|_| !rng.chance(0)));
        assert!((0..200).all(|_| rng.chance(1000)));
    }

    #[test]
    fn mix_varies_with_index() {
        assert_ne!(mix(1, 0), mix(1, 1));
        assert_eq!(mix(1, 5), mix(1, 5));
    }
}
