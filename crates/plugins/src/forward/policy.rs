//! Upstream selection and query matching shared by `forward` and `grpc`
//! (both plugins have the same `policy` and `except` options).

use std::sync::atomic::{AtomicU32, Ordering};

use kerndns_core::zones::is_subdomain;
use kerndns_core::{Controller, SetupError};

use super::proxy::rand_below;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Random,
    RoundRobin,
    Sequential,
}

impl Policy {
    /// The name used in the Corefile.
    pub fn as_str(&self) -> &'static str {
        match self {
            Policy::Random => "random",
            Policy::RoundRobin => "round_robin",
            Policy::Sequential => "sequential",
        }
    }

    /// `policy random|round_robin|sequential`, after the `policy` token.
    pub fn parse(c: &mut Controller<'_>) -> Result<Policy, SetupError> {
        if !c.next_arg() {
            return Err(c.arg_err());
        }
        Ok(match c.val() {
            "random" => Policy::Random,
            "round_robin" => Policy::RoundRobin,
            "sequential" => Policy::Sequential,
            x => {
                let msg = format!("unknown policy '{x}'");
                return Err(c.errf(msg));
            }
        })
    }
}

/// A policy with its round-robin counter.
#[derive(Debug)]
pub struct Picker {
    pub policy: Policy,
    robin: AtomicU32,
}

impl Picker {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            robin: AtomicU32::new(0),
        }
    }

    /// `p` in the order the policy wants it tried.
    pub fn list<T: Clone>(&self, p: &[T]) -> Vec<T> {
        if p.is_empty() {
            return Vec::new();
        }
        match self.policy {
            Policy::Sequential => p.to_vec(),
            Policy::RoundRobin => {
                let i = (self.robin.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as usize) % p.len();
                let mut v = Vec::with_capacity(p.len());
                v.push(p[i].clone());
                v.extend(p[..i].iter().cloned());
                v.extend(p[i + 1..].iter().cloned());
                v
            }
            Policy::Random => {
                let mut v = p.to_vec();
                for i in (1..v.len()).rev() {
                    v.swap(i, rand_below(i + 1));
                }
                v
            }
        }
    }
}

/// Whether a stanza for `from` with `except` names `ignored` handles
/// `name` (all lowercase FQDNs): `from` itself always, names below it
/// unless they are at or below an ignored name.
pub fn matches(from: &str, ignored: &[String], name: &str) -> bool {
    if !is_subdomain(from, name) {
        return false;
    }
    if name == from {
        return true;
    }
    !ignored.iter().any(|i| is_subdomain(i, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_permutation(a: &[u8], b: &[u8]) -> bool {
        let (mut a, mut b) = (a.to_vec(), b.to_vec());
        a.sort();
        b.sort();
        a == b
    }

    // policy_test.go
    #[test]
    fn empty() {
        for p in [Policy::Random, Policy::RoundRobin, Policy::Sequential] {
            assert!(Picker::new(p).list::<u8>(&[]).is_empty());
        }
    }

    #[test]
    fn ordering() {
        let input = [0u8, 1, 2];
        assert_eq!(Picker::new(Policy::Sequential).list(&input), input);

        let r = Picker::new(Policy::RoundRobin);
        let got: Vec<_> = (0..3).map(|_| r.list(&input)).collect();
        for g in &got {
            assert!(is_permutation(&input, g));
        }
        assert_eq!([got[0][0], got[1][0], got[2][0]], [1, 2, 0]);

        let r = Picker::new(Policy::Random);
        assert!(is_permutation(&input, &r.list(&input)));
        assert!(is_permutation(&input[..2], &r.list(&input[..2])));
    }

    #[test]
    fn matching() {
        let ignored = vec!["internal.example.org.".to_string()];
        assert!(matches("example.org.", &ignored, "www.example.org."));
        assert!(!matches("example.org.", &ignored, "a.internal.example.org."));
        assert!(!matches("example.org.", &ignored, "example.net."));
        assert!(matches(".", &["example.org.".into()], "."));
    }
}
