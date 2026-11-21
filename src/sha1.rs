pub const ZERO_OID: [u8; 20] = [0u8; 20];
pub const ZERO_OID_HEX: &str = "0000000000000000000000000000000000000000";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjKind::Commit => "commit",
            ObjKind::Tree => "tree",
            ObjKind::Blob => "blob",
            ObjKind::Tag => "tag",
        }
    }

    pub fn from_pack_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(ObjKind::Commit),
            2 => Some(ObjKind::Tree),
            3 => Some(ObjKind::Blob),
            4 => Some(ObjKind::Tag),
            _ => None,
        }
    }
}

pub struct Sha1 {
    state: [u32; 5],
    len_bytes: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha1 {
    #[inline]
    pub fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            len_bytes: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    #[inline]
    pub fn update(&mut self, mut data: &[u8]) {
        self.len_bytes += data.len() as u64;
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            compress_block(&mut self.state, &block);
            self.buf_len = 0;
            data = &data[need..];
        }
        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            compress_block(&mut self.state, block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let total_bits = self.len_bytes * 8;
        self.update(&[0x80]);
        let pad_zeroes = if self.buf_len <= 56 {
            56 - self.buf_len
        } else {
            64 - self.buf_len + 56
        };
        if pad_zeroes > 0 {
            let zeroes = [0u8; 64];
            let mut rem = pad_zeroes;
            while rem > 0 {
                let take = rem.min(64);
                self.update(&zeroes[..take]);
                rem -= take;
            }
        }
        let len_be = total_bits.to_be_bytes();
        self.update(&len_be);

        let mut out = [0u8; 20];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

#[inline(always)]
fn compress_block(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
            _ => (b ^ c ^ d, 0xCA62_C1D6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

pub fn hash_git_object(kind: ObjKind, data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    let mut len_buf = itoa::Buffer::new();
    h.update(kind.as_str().as_bytes());
    h.update(b" ");
    h.update(len_buf.format(data.len()).as_bytes());
    h.update(&[0]);
    h.update(data);
    h.finalize()
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[inline]
pub fn oid_to_hex(oid: &[u8; 20]) -> [u8; 40] {
    let mut out = [0u8; 40];
    for (i, &b) in oid.iter().enumerate() {
        out[i * 2] = HEX_CHARS[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS[(b & 0x0f) as usize];
    }
    out
}

pub fn oid_to_string(oid: &[u8; 20]) -> String {
    let hex = oid_to_hex(oid);
    // Safe: HEX_CHARS only produces lowercase ASCII hex digits.
    unsafe { String::from_utf8_unchecked(hex.to_vec()) }
}

pub fn write_oid_hex(buf: &mut Vec<u8>, oid: &[u8; 20]) {
    let hex = oid_to_hex(oid);
    buf.extend_from_slice(&hex);
}

#[inline]
pub fn hex_to_oid(hex: &[u8]) -> Option<[u8; 20]> {
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline(always)]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
