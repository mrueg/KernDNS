//! The bits of the protobuf wire format KernDNS needs, written by hand
//! instead of generated: CoreDNS's `pb.DnsPacket { bytes msg = 1; }` (the
//! gRPC listener and the `grpc` plugin) and dnstap's `Dnstap` and
//! `Message` (the `dnstap` plugin). Fields are written in field-number
//! order, like Go's `proto.Marshal`.

/// Append `v` as a base-128 varint.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Read a varint from the front of `b`.
pub fn get_varint(b: &mut &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = b.split_first()?;
        *b = rest;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// A varint field (wire type 0).
pub fn put_varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
    put_varint(out, u64::from(field) << 3);
    put_varint(out, v);
}

/// A length-delimited field (wire type 2): bytes, strings, messages.
pub fn put_bytes_field(out: &mut Vec<u8>, field: u32, v: &[u8]) {
    put_varint(out, (u64::from(field) << 3) | 2);
    put_varint(out, v.len() as u64);
    out.extend_from_slice(v);
}

/// A fixed32 field (wire type 5).
pub fn put_fixed32_field(out: &mut Vec<u8>, field: u32, v: u32) {
    put_varint(out, (u64::from(field) << 3) | 5);
    out.extend_from_slice(&v.to_le_bytes());
}

/// One field read by [`next_field`].
#[derive(Debug, PartialEq, Eq)]
pub enum Field<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

/// Read the next field from `b`: its number and value. `None` on
/// malformed input.
pub fn next_field<'a>(b: &mut &'a [u8]) -> Option<(u32, Field<'a>)> {
    let key = get_varint(b)?;
    let field = u32::try_from(key >> 3).ok().filter(|f| *f != 0)?;
    let v = match key & 7 {
        0 => Field::Varint(get_varint(b)?),
        1 => {
            let (v, rest) = b.split_first_chunk::<8>()?;
            *b = rest;
            Field::Fixed64(u64::from_le_bytes(*v))
        }
        2 => {
            let n = usize::try_from(get_varint(b)?).ok()?;
            if b.len() < n {
                return None;
            }
            let (v, rest) = b.split_at(n);
            *b = rest;
            Field::Bytes(v)
        }
        5 => {
            let (v, rest) = b.split_first_chunk::<4>()?;
            *b = rest;
            Field::Fixed32(u32::from_le_bytes(*v))
        }
        _ => return None,
    };
    Some((field, v))
}

/// `DnsPacket{msg}` in protobuf (proto3 leaves out an empty field).
pub fn encode_packet(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 4);
    if !msg.is_empty() {
        put_bytes_field(&mut out, 1, msg);
    }
    out
}

/// The `msg` field of a `DnsPacket`; unknown fields are skipped.
pub fn decode_packet(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut msg = Vec::new();
    while !b.is_empty() {
        if let (1, Field::Bytes(v)) = next_field(&mut b)? {
            msg = v.to_vec();
        }
    }
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet() {
        let msg = vec![7u8; 300];
        let pb = encode_packet(&msg);
        assert_eq!(&pb[..3], &[0x0a, 0xac, 0x02]);
        assert_eq!(decode_packet(&pb), Some(msg));
        assert_eq!(encode_packet(&[]), Vec::<u8>::new());
        assert_eq!(decode_packet(&[]), Some(vec![]));
        // unknown varint field 2, then msg
        assert_eq!(decode_packet(&[0x10, 0x05, 0x0a, 0x01, 0x09]), Some(vec![9]));
        assert_eq!(decode_packet(&[0x0a, 0x05, 0x01]), None);
    }

    #[test]
    fn fields() {
        let mut out = Vec::new();
        put_varint_field(&mut out, 15, 1);
        put_fixed32_field(&mut out, 9, 0x01020304);
        put_bytes_field(&mut out, 14, b"ab");
        let mut b = &out[..];
        assert_eq!(next_field(&mut b), Some((15, Field::Varint(1))));
        assert_eq!(next_field(&mut b), Some((9, Field::Fixed32(0x01020304))));
        assert_eq!(next_field(&mut b), Some((14, Field::Bytes(b"ab"))));
        assert!(b.is_empty());
        assert_eq!(next_field(&mut &[0x08][..]), None);
    }
}
