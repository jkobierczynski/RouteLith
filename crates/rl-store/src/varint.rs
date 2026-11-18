//! LEB128 varints and zigzag encoding.

/// Append `v` as an unsigned LEB128 varint.
pub(crate) fn put_u64(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub(crate) fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, zigzag(v));
}

pub(crate) fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

pub(crate) fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// A cursor over encoded bytes. Every read is bounds-checked and returns
/// `None` on truncated or malformed input; nothing panics.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            let bits = u64::from(b & 0x7f);
            // The tenth byte may only carry the top bit.
            if shift == 63 && bits > 1 {
                return None;
            }
            v |= bits << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    pub(crate) fn i64(&mut self) -> Option<i64> {
        self.u64().map(unzigzag)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        u32::try_from(self.u64()?).ok()
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        u16::try_from(self.u64()?).ok()
    }

    pub(crate) fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn u64_round_trips(v: u64) {
            let mut b = Vec::new();
            put_u64(&mut b, v);
            let mut r = Reader::new(&b);
            prop_assert_eq!(r.u64(), Some(v));
            prop_assert!(r.is_empty());
        }

        #[test]
        fn i64_round_trips(v: i64) {
            let mut b = Vec::new();
            put_i64(&mut b, v);
            prop_assert_eq!(Reader::new(&b).i64(), Some(v));
        }

        #[test]
        fn garbage_never_panics(b: Vec<u8>) {
            let mut r = Reader::new(&b);
            while r.u64().is_some() {}
        }
    }

    #[test]
    fn small_values_are_one_byte() {
        let mut b = Vec::new();
        put_i64(&mut b, 0);
        put_i64(&mut b, -1);
        put_i64(&mut b, 63);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn overlong_is_rejected() {
        assert_eq!(Reader::new(&[0xff; 11]).u64(), None);
        assert_eq!(Reader::new(&[0x80]).u64(), None);
    }

    #[test]
    fn tenth_byte_rules() {
        let mut max = [0xffu8; 10];
        max[9] = 0x01;
        assert_eq!(Reader::new(&max).u64(), Some(u64::MAX));
        // More than the top bit in the tenth byte.
        max[9] = 0x02;
        assert_eq!(Reader::new(&max).u64(), None);
        // A continuation bit on the tenth byte.
        max[9] = 0x81;
        assert_eq!(Reader::new(&max).u64(), None);
    }
}
