//! CIDR helpers with the semantics of Go's `net` package, on `ipnet`.

use std::net::IpAddr;

pub use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// `net.ParseCIDR`: the network (the address masked to the prefix
/// length), with Go's error message.
pub fn parse_cidr(s: &str) -> Result<IpNet, String> {
    let err = || format!("invalid CIDR address: {s}");
    let (addr, bits) = s.split_once('/').ok_or_else(err)?;
    // Go's dtoi takes decimal digits only, no sign
    if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err());
    }
    let ip: IpAddr = addr.parse().map_err(|_| err())?;
    let net = IpNet::new(ip, bits.parse().map_err(|_| err())?).map_err(|_| err())?;
    Ok(net.trunc())
}

/// `(*net.IPNet).Contains`: an IPv4-mapped IPv6 address, or network of at
/// least 96 bits, counts as IPv4.
pub fn contains(net: &IpNet, ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    match (net, net.network().to_canonical()) {
        (IpNet::V6(n), IpAddr::V4(v4)) => IpNet::new(v4.into(), n.prefix_len() - 96).is_ok_and(|n| n.contains(&ip)),
        _ => net.contains(&ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_cidr("10.1.2.3/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(parse_cidr("2001:db8::1/32").unwrap().to_string(), "2001:db8::/32");
        assert_eq!(
            parse_cidr("::ffff:1.2.3.4/120").unwrap().to_string(),
            "::ffff:1.2.3.0/120"
        );
        for bad in [
            "10.0.0.0",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/33",
            "::/129",
            "x/8",
            "fe80::1%eth0/64",
        ] {
            assert_eq!(parse_cidr(bad), Err(format!("invalid CIDR address: {bad}")));
        }
    }

    #[test]
    fn contains_like_go() {
        let n = |s| parse_cidr(s).unwrap();
        let ip = |s: &str| s.parse().unwrap();
        assert!(contains(&n("10.0.0.0/8"), ip("10.1.2.3")));
        assert!(!contains(&n("10.0.0.0/8"), ip("11.1.2.3")));
        assert!(contains(&n("10.0.0.0/8"), ip("::ffff:10.1.2.3")));
        assert!(contains(&n("::ffff:10.0.0.0/104"), ip("10.1.2.3")));
        assert!(!contains(&n("::/0"), ip("10.1.2.3")));
        assert!(!contains(&n("::/0"), ip("::ffff:10.1.2.3")));
        assert!(contains(&n("::/0"), ip("2001:db8::1")));
        assert!(!contains(&n("0.0.0.0/0"), ip("2001:db8::1")));
    }
}
