use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use rustc_hash::FxHashMap;

use crate::sha1::{hash_git_object, oid_to_string, ObjKind, Sha1};

#[derive(Clone)]
pub struct DecodedObject {
    pub oid: [u8; 20],
    pub kind: ObjKind,
    pub data: Vec<u8>,
}

pub struct PackDecoder {
    decomp: Decompress,
    scratch: Vec<u8>,
}

impl PackDecoder {
    pub fn new() -> Self {
        Self {
            decomp: Decompress::new(true),
            scratch: Vec::with_capacity(8192),
        }
    }

    pub fn decode_pack<F>(
        &mut self,
        pack: &[u8],
        resolve_external: F,
    ) -> Result<Vec<DecodedObject>, String>
    where
        F: Fn(&[u8; 20]) -> Option<(ObjKind, Vec<u8>)>,
    {
        if pack.len() < 32 {
            return Err("Packfile too short".to_string());
        }
        if &pack[0..4] != b"PACK" {
            return Err("Missing PACK magic".to_string());
        }
        let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
        if version != 2 && version != 3 {
            return Err(format!("Unsupported pack version {version}"));
        }
        let count = u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]) as usize;

        let payload_end = pack.len() - 20;
        let payload = &pack[..payload_end];
        let actual_trailer = Sha1::digest(payload);
        if actual_trailer != pack[payload_end..] {
            return Err("Packfile checksum mismatch".to_string());
        }

        if count == 0 {
            return Ok(Vec::new());
        }

        enum EntrySpec {
            Base { kind: ObjKind },
            OfsDelta { base_offset: usize },
            RefDelta { base_oid: [u8; 20] },
        }

        struct RawEntry {
            offset: usize,
            spec: EntrySpec,
            data: Vec<u8>,
        }

        // Fast path for base-only packs (such as bench pushes): avoid allocating
        // delta tracking maps unless an OFS_DELTA or REF_DELTA actually appears.
        let mut base_objs: Vec<DecodedObject> = Vec::with_capacity(count.min(4096));
        let mut base_offsets: Vec<usize> = Vec::with_capacity(count.min(4096));

        let mut delta_mode = false;
        let mut entries: Vec<RawEntry> = Vec::new();
        let mut by_offset: FxHashMap<usize, usize> = FxHashMap::default();
        let mut by_oid: FxHashMap<[u8; 20], usize> = FxHashMap::default();
        let mut resolved: Vec<Option<(ObjKind, Vec<u8>, [u8; 20])>> = Vec::new();

        let mut pos = 12usize;
        for _ in 0..count {
            if pos >= payload.len() {
                return Err("Packfile truncated before declared object count".to_string());
            }
            let entry_offset = pos;
            let mut b = payload[pos];
            pos += 1;
            let type_code = (b >> 4) & 7;
            let mut declared_size = (b & 0x0f) as usize;
            let mut shift = 4u32;
            while (b & 0x80) != 0 {
                if pos >= payload.len() {
                    return Err("Truncated object header in packfile".to_string());
                }
                b = payload[pos];
                pos += 1;
                if shift < usize::BITS {
                    declared_size |= ((b & 0x7f) as usize) << shift;
                }
                shift += 7;
            }

            if !delta_mode && (1..=4).contains(&type_code) {
                let kind = ObjKind::from_pack_code(type_code).unwrap();
                let (out_len, consumed) = self.inflate_into_scratch(&payload[pos..], declared_size)?;
                pos += consumed;
                let inflated = &self.scratch[..out_len];
                let oid = hash_git_object(kind, inflated);
                base_offsets.push(entry_offset);
                base_objs.push(DecodedObject {
                    oid,
                    kind,
                    data: inflated.to_vec(),
                });
                continue;
            }

            let spec = match type_code {
                1..=4 => EntrySpec::Base {
                    kind: ObjKind::from_pack_code(type_code).unwrap(),
                },
                6 => {
                    if pos >= payload.len() {
                        return Err("Truncated OFS_DELTA offset".to_string());
                    }
                    let mut c = payload[pos];
                    pos += 1;
                    let mut back = (c & 0x7f) as usize;
                    while (c & 0x80) != 0 {
                        if pos >= payload.len() {
                            return Err("Truncated OFS_DELTA offset varint".to_string());
                        }
                        c = payload[pos];
                        pos += 1;
                        back = ((back + 1) << 7) | ((c & 0x7f) as usize);
                    }
                    let base_offset = entry_offset
                        .checked_sub(back)
                        .ok_or_else(|| "OFS_DELTA underflow".to_string())?;
                    EntrySpec::OfsDelta { base_offset }
                }
                7 => {
                    if pos + 20 > payload.len() {
                        return Err("Truncated REF_DELTA base OID".to_string());
                    }
                    let mut base_oid = [0u8; 20];
                    base_oid.copy_from_slice(&payload[pos..pos + 20]);
                    pos += 20;
                    EntrySpec::RefDelta { base_oid }
                }
                _ => return Err(format!("Unsupported pack object type {type_code}")),
            };

            if !delta_mode {
                delta_mode = true;
                let extra_rem = count.saturating_sub(base_objs.len()).min(4096);
                entries.reserve(base_objs.len() + extra_rem);
                resolved.reserve(base_objs.len() + extra_rem);
                for (i, obj) in base_objs.drain(..).enumerate() {
                    let off = base_offsets[i];
                    by_offset.insert(off, i);
                    by_oid.insert(obj.oid, i);
                    resolved.push(Some((obj.kind, obj.data, obj.oid)));
                    entries.push(RawEntry {
                        offset: off,
                        spec: EntrySpec::Base { kind: obj.kind },
                        data: Vec::new(),
                    });
                }
            }

            let (out_len, consumed) = self.inflate_into_scratch(&payload[pos..], declared_size)?;
            pos += consumed;
            let inflated = self.scratch[..out_len].to_vec();

            let idx = entries.len();
            match &spec {
                EntrySpec::Base { kind } => {
                    let oid = hash_git_object(*kind, &inflated);
                    by_offset.insert(entry_offset, idx);
                    by_oid.insert(oid, idx);
                    resolved.push(Some((*kind, inflated, oid)));
                    entries.push(RawEntry {
                        offset: entry_offset,
                        spec,
                        data: Vec::new(),
                    });
                }
                EntrySpec::OfsDelta { .. } | EntrySpec::RefDelta { .. } => {
                    resolved.push(None);
                    entries.push(RawEntry {
                        offset: entry_offset,
                        spec,
                        data: inflated,
                    });
                }
            }
        }

        if !delta_mode {
            return Ok(base_objs);
        }

        let mut remaining = entries
            .iter()
            .enumerate()
            .filter_map(|(i, _)| if resolved[i].is_none() { Some(i) } else { None })
            .collect::<Vec<_>>();

        while !remaining.is_empty() {
            let mut next_remaining = Vec::new();
            let mut progressed = false;

            for idx in remaining {
                let (base_kind, base_bytes) = match &entries[idx].spec {
                    EntrySpec::OfsDelta { base_offset } => {
                        if let Some(&b_idx) = by_offset.get(base_offset) {
                            if let Some((k, ref d, _)) = resolved[b_idx] {
                                (k, d.clone())
                            } else {
                                next_remaining.push(idx);
                                continue;
                            }
                        } else {
                            return Err("Missing OFS_DELTA base".to_string());
                        }
                    }
                    EntrySpec::RefDelta { base_oid } => {
                        if let Some(&b_idx) = by_oid.get(base_oid) {
                            if let Some((k, ref d, _)) = resolved[b_idx] {
                                (k, d.clone())
                            } else {
                                next_remaining.push(idx);
                                continue;
                            }
                        } else if let Some((k, ext_bytes)) = resolve_external(base_oid) {
                            (k, ext_bytes)
                        } else {
                            return Err(format!("Missing REF_DELTA base {}", oid_to_string(base_oid)));
                        }
                    }
                    EntrySpec::Base { .. } => unreachable!(),
                };

                let target = apply_git_delta(&base_bytes, &entries[idx].data)?;
                let oid = hash_git_object(base_kind, &target);
                by_offset.insert(entries[idx].offset, idx);
                by_oid.insert(oid, idx);
                resolved[idx] = Some((base_kind, target, oid));
                entries[idx].data.clear();
                progressed = true;
            }

            if !progressed {
                return Err("Cyclic or unresolvable delta chain in packfile".to_string());
            }
            remaining = next_remaining;
        }

        let mut out = Vec::with_capacity(resolved.len());
        for item in resolved {
            let (kind, data, oid) = item.unwrap();
            out.push(DecodedObject { oid, kind, data });
        }
        Ok(out)
    }

    fn inflate_into_scratch(&mut self, input: &[u8], declared_size: usize) -> Result<(usize, usize), String> {
        self.decomp.reset(true);
        let init_cap = declared_size.max(256).min(8 * 1024 * 1024);
        if self.scratch.len() < init_cap {
            self.scratch.resize(init_cap, 0);
        }
        let mut in_pos = 0usize;
        let mut out_pos = 0usize;

        loop {
            if out_pos == self.scratch.len() {
                let next_len = self.scratch.len().saturating_mul(2).max(out_pos + 256);
                self.scratch.resize(next_len, 0);
            }
            let before_in = self.decomp.total_in();
            let before_out = self.decomp.total_out();
            let status = self
                .decomp
                .decompress(&input[in_pos..], &mut self.scratch[out_pos..], FlushDecompress::None)
                .map_err(|e| format!("zlib inflate error: {e}"))?;
            let consumed_now = (self.decomp.total_in() - before_in) as usize;
            let produced_now = (self.decomp.total_out() - before_out) as usize;
            in_pos += consumed_now;
            out_pos += produced_now;

            match status {
                Status::StreamEnd => return Ok((out_pos, in_pos)),
                Status::Ok => {
                    if consumed_now == 0 && produced_now == 0 && in_pos >= input.len() {
                        return Err("Truncated zlib stream in packfile".to_string());
                    }
                }
                Status::BufError => {
                    if out_pos == self.scratch.len() {
                        continue;
                    }
                    if in_pos >= input.len() {
                        return Err("Truncated zlib stream in packfile".to_string());
                    }
                    return Err("zlib inflate buffer error".to_string());
                }
            }
        }
    }
}

fn read_delta_varint(buf: &[u8], pos: &mut usize) -> Result<usize, String> {
    let mut val = 0usize;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err("Truncated varint in delta".to_string());
        }
        let b = buf[*pos];
        *pos += 1;
        if shift < usize::BITS {
            val |= ((b & 0x7f) as usize) << shift;
        }
        if (b & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn apply_git_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0usize;
    let src_len = read_delta_varint(delta, &mut pos)?;
    if src_len != base.len() {
        return Err(format!("Delta base length mismatch: expected {src_len}, got {}", base.len()));
    }
    let dst_len = read_delta_varint(delta, &mut pos)?;
    let mut out = Vec::with_capacity(dst_len);

    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if (cmd & 0x80) != 0 {
            let mut copy_off = 0usize;
            let mut copy_size = 0usize;
            for bit in 0..4u32 {
                if (cmd & (1 << bit)) != 0 {
                    if pos >= delta.len() {
                        return Err("Truncated delta copy offset".to_string());
                    }
                    copy_off |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3u32 {
                if (cmd & (1 << (bit + 4))) != 0 {
                    if pos >= delta.len() {
                        return Err("Truncated delta copy size".to_string());
                    }
                    copy_size |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let end = copy_off
                .checked_add(copy_size)
                .ok_or_else(|| "Delta copy overflow".to_string())?;
            if end > base.len() {
                return Err("Delta copy out of bounds".to_string());
            }
            out.extend_from_slice(&base[copy_off..end]);
        } else if cmd > 0 {
            let add_len = cmd as usize;
            if pos + add_len > delta.len() {
                return Err("Delta insert out of bounds".to_string());
            }
            out.extend_from_slice(&delta[pos..pos + add_len]);
            pos += add_len;
        } else {
            return Err("Invalid delta instruction opcode 0".to_string());
        }
    }

    if out.len() != dst_len {
        return Err(format!("Delta target length mismatch: wrote {}, expected {dst_len}", out.len()));
    }
    Ok(out)
}

pub fn deflate_best(data: &[u8]) -> Vec<u8> {
    let mut comp = Compress::new(Compression::best(), true);
    let mut out = vec![0u8; data.len() + 64];
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    loop {
        if out_pos == out.len() {
            out.resize(out.len() * 2 + 64, 0);
        }
        let flush = if in_pos >= data.len() {
            FlushCompress::Finish
        } else {
            FlushCompress::None
        };
        let b_in = comp.total_in();
        let b_out = comp.total_out();
        let st = comp
            .compress(&data[in_pos..], &mut out[out_pos..], flush)
            .expect("zlib compress");
        in_pos += (comp.total_in() - b_in) as usize;
        out_pos += (comp.total_out() - b_out) as usize;
        if matches!(st, Status::StreamEnd) {
            break;
        }
    }
    out.truncate(out_pos);
    out
}

#[inline]
pub fn push_pack_obj_header(out: &mut Vec<u8>, kind: ObjKind, size: usize) {
    let type_code = kind as u8;
    let mut byte = ((type_code & 7) << 4) | ((size & 0x0f) as u8);
    let mut rem = size >> 4;
    while rem > 0 {
        out.push(byte | 0x80);
        byte = (rem & 0x7f) as u8;
        rem >>= 7;
    }
    out.push(byte);
}

pub fn finalize_pack(mut buf: Vec<u8>, count: u32) -> Vec<u8> {
    buf[0..4].copy_from_slice(b"PACK");
    buf[4..8].copy_from_slice(&2u32.to_be_bytes());
    buf[8..12].copy_from_slice(&count.to_be_bytes());
    let trailer = Sha1::digest(&buf);
    buf.extend_from_slice(&trailer);
    buf
}

pub fn empty_packfile() -> Vec<u8> {
    finalize_pack(vec![0u8; 12], 0)
}
