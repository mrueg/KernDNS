//! Randomness from the thread-local, OS-seeded CSPRNG ([`rand::rng`]).
//!
//! DNS message ids must be unpredictable: an off-path attacker who can guess
//! the id of an upstream query can race a forged answer into the cache.
//! miekg/dns draws ids from `crypto/rand` for the same reason.

/// A random 16-bit message id, like miekg/dns's `dns.Id`.
pub fn rand_id() -> u16 {
    rand::random()
}

/// A random index below `n` (0 if `n` is 0 or 1), like Go's `rand.Intn`.
pub fn rand_below(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    rand::random_range(0..n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_not_sequential_and_cover_the_space() {
        let ids: Vec<u16> = (0..4096).map(|_| rand_id()).collect();
        // consecutive ids are neither equal nor a fixed step apart
        let steps: std::collections::HashSet<u16> = ids.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
        assert!(steps.len() > 1000, "{} distinct steps", steps.len());
        // both halves of each byte get used
        let or = ids.iter().fold(0, |a, &i| a | i);
        let and = ids.iter().fold(u16::MAX, |a, &i| a & i);
        assert_eq!((or, and), (u16::MAX, 0));
    }

    #[test]
    fn below() {
        assert_eq!(rand_below(0), 0);
        assert_eq!(rand_below(1), 0);
        let mut seen = [false; 5];
        for _ in 0..1000 {
            seen[rand_below(5)] = true;
        }
        assert_eq!(seen, [true; 5]);
    }
}
