//! Streaming Reed-Solomon k-of-n split/join over fixed-size stripes.
//!
//! Each stripe is split into `n` equal-length shards (k data + n-k parity).
//! Shards are written as BLAKE3-framed records (see `docs/FORMAT.md`).

use crate::error::{Error, Result};
use crate::format::{parse_chunk_frame, write_chunk_frame, ChunkFrame};
use crate::sss::validate_threshold;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io::{Read, Write};
use zeroize::Zeroize;

/// Default stripe size: 4 MiB.
pub const DEFAULT_STRIPE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum accepted framed shard payload (64 MiB).
const MAX_SHARD_PAYLOAD: usize = 64 * 1024 * 1024;

/// Split a ciphertext/plaintext stream into `n` share writers.
///
/// Writers must be provided in share-index order `0..n`. Each stripe is padded
/// with zeros to a multiple of `k` before sharding; the original stripe length
/// is recorded in the frame so join can trim padding.
pub fn split_stripes<R: Read, W: Write>(
    mut input: R,
    outputs: &mut [W],
    k: usize,
    n: usize,
    stripe_size: usize,
) -> Result<u64> {
    validate_threshold(k, n)?;
    if outputs.len() != n {
        return Err(Error::InvalidParameter("outputs.len() must equal n"));
    }
    if stripe_size == 0 || stripe_size > MAX_SHARD_PAYLOAD {
        return Err(Error::InvalidParameter("stripe_size out of range"));
    }
    if stripe_size % k != 0 {
        return Err(Error::InvalidParameter(
            "stripe_size must be divisible by k",
        ));
    }

    let parity = n - k;
    let rs = if parity > 0 {
        Some(ReedSolomon::new(k, parity).map_err(Error::from_rs)?)
    } else {
        None
    };
    let shard_size = stripe_size / k;

    let mut buf = vec![0u8; stripe_size];
    let mut stripe_index: u64 = 0;
    let mut total: u64 = 0;

    loop {
        let nread = read_fill(&mut input, &mut buf)?;
        if nread == 0 {
            break;
        }
        total = total.saturating_add(nread as u64);

        // Zero-pad the remainder of the stripe.
        if nread < stripe_size {
            buf[nread..].fill(0);
        }

        let mut shards: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                if i < k {
                    buf[i * shard_size..(i + 1) * shard_size].to_vec()
                } else {
                    vec![0u8; shard_size]
                }
            })
            .collect();

        if let Some(ref rs) = rs {
            let mut refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut_slice()).collect();
            rs.encode(&mut refs).map_err(Error::from_rs)?;
        }

        for (share_index, shard) in shards.iter().enumerate() {
            let frame = ChunkFrame {
                version: 1,
                stripe_index,
                original_stripe_len: nread as u32,
                shard_len: shard.len() as u32,
                hash: blake3_hash(shard),
                data: shard.clone(),
            };
            write_chunk_frame(&mut outputs[share_index], &frame)?;
        }

        for s in shards.iter_mut() {
            s.zeroize();
        }
        stripe_index = stripe_index
            .checked_add(1)
            .ok_or(Error::InvalidParameter("stripe index overflow"))?;

        if nread < stripe_size {
            break;
        }
    }

    buf.zeroize();
    for w in outputs.iter_mut() {
        w.flush()?;
    }
    Ok(total)
}

/// Reconstruct the original stream from any `k` share readers.
///
/// `share_indices` gives the share index (0..n-1) for each reader. All readers
/// must present the same sequence of stripe_index values.
pub fn join_stripes<R: Read, W: Write>(
    inputs: &mut [R],
    share_indices: &[u8],
    output: &mut W,
    k: usize,
    n: usize,
) -> Result<u64> {
    validate_threshold(k, n)?;
    if inputs.len() != k || share_indices.len() != k {
        return Err(Error::NotEnoughShares {
            need: k,
            have: inputs.len(),
        });
    }
    // Distinct indices in range.
    let mut seen = [false; 256];
    for &idx in share_indices {
        if idx as usize >= n {
            return Err(Error::InvalidParameter("share index out of range"));
        }
        if seen[idx as usize] {
            return Err(Error::InvalidParameter("duplicate share index"));
        }
        seen[idx as usize] = true;
    }

    let parity = n - k;
    let rs = if parity > 0 {
        Some(ReedSolomon::new(k, parity).map_err(Error::from_rs)?)
    } else {
        None
    };
    let mut total: u64 = 0;
    let mut expected_stripe: u64 = 0;
    let mut finished = false;

    while !finished {
        let mut frames: Vec<Option<ChunkFrame>> = (0..n).map(|_| None).collect();
        let mut original_len: Option<u32> = None;
        let mut shard_len: Option<usize> = None;
        let mut got = 0usize;

        for (reader_i, reader) in inputs.iter_mut().enumerate() {
            match parse_chunk_frame(reader) {
                Ok(frame) => {
                    if frame.stripe_index != expected_stripe {
                        return Err(Error::Format("stripe_index mismatch"));
                    }
                    if frame.data.len() != frame.shard_len as usize {
                        return Err(Error::Format("shard_len mismatch"));
                    }
                    if frame.data.len() > MAX_SHARD_PAYLOAD {
                        return Err(Error::LengthBound {
                            declared: frame.data.len() as u64,
                            max: MAX_SHARD_PAYLOAD as u64,
                        });
                    }
                    let h = blake3_hash(&frame.data);
                    if h != frame.hash {
                        return Err(Error::Integrity);
                    }
                    match original_len {
                        Some(l) if l != frame.original_stripe_len => {
                            return Err(Error::Format("original_stripe_len mismatch"));
                        }
                        None => original_len = Some(frame.original_stripe_len),
                        _ => {}
                    }
                    match shard_len {
                        Some(l) if l != frame.data.len() => {
                            return Err(Error::Format("inconsistent shard lengths"));
                        }
                        None => shard_len = Some(frame.data.len()),
                        _ => {}
                    }
                    let idx = share_indices[reader_i] as usize;
                    frames[idx] = Some(frame);
                    got += 1;
                }
                Err(Error::UnexpectedEof) if expected_stripe == 0 && got == 0 && reader_i == 0 => {
                    // Empty input stream.
                    return Ok(0);
                }
                Err(Error::UnexpectedEof) if got == 0 && reader_i == 0 => {
                    finished = true;
                    break;
                }
                Err(Error::UnexpectedEof) => {
                    return Err(Error::Format("truncated share stream at stripe boundary"));
                }
                Err(e) => return Err(e),
            }
        }

        if finished {
            break;
        }
        if got != k {
            return Err(Error::NotEnoughShares { need: k, have: got });
        }

        let shard_len = shard_len.ok_or(Error::Format("missing shard_len"))?;
        let original_len = original_len.ok_or(Error::Format("missing original_stripe_len"))?;

        // Build shard slots: present shares filled, others None for reconstruct.
        let mut shards: Vec<Option<Vec<u8>>> = (0..n)
            .map(|i| frames[i].as_ref().map(|f| f.data.clone()))
            .collect();

        if let Some(ref rs) = rs {
            rs.reconstruct(&mut shards).map_err(Error::from_rs)?;
        } else {
            // k == n: all data shards must be present; no parity.
            for (i, slot) in shards.iter().enumerate().take(k) {
                if slot.is_none() {
                    return Err(Error::NotEnoughShares { need: k, have: i });
                }
            }
        }

        let mut stripe = Vec::with_capacity(k * shard_len);
        for shard in shards.iter().take(k) {
            let shard = shard.as_ref().ok_or(Error::ReedSolomon(
                "missing data shard after reconstruct".into(),
            ))?;
            stripe.extend_from_slice(shard);
        }

        if original_len as usize > stripe.len() {
            return Err(Error::Format("original_stripe_len exceeds reconstructed"));
        }
        output.write_all(&stripe[..original_len as usize])?;
        total = total.saturating_add(original_len as u64);

        if (original_len as usize) < k * shard_len {
            // Last (short) stripe.
            finished = true;
        }

        for s in shards.iter_mut().flatten() {
            s.zeroize();
        }
        expected_stripe = expected_stripe
            .checked_add(1)
            .ok_or(Error::InvalidParameter("stripe index overflow"))?;
    }

    output.flush()?;
    Ok(total)
}

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn read_fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rs_roundtrip_any_k_of_n() {
        let data = vec![0xABu8; 96];
        let k = 3usize;
        let n = 5usize;
        let stripe = 48; // divisible by k
        let mut outputs: Vec<Vec<u8>> = (0..n).map(|_| Vec::new()).collect();
        {
            let refs: Vec<&mut Vec<u8>> = outputs.iter_mut().collect();
            let _ = refs;
        }
        let mut out_bufs: Vec<Cursor<Vec<u8>>> = (0..n).map(|_| Cursor::new(Vec::new())).collect();
        split_stripes(Cursor::new(&data), &mut out_bufs, k, n, stripe).unwrap();

        // Take shares 1, 3, 4
        let indices = [1u8, 3, 4];
        let mut readers: Vec<Cursor<Vec<u8>>> = indices
            .iter()
            .map(|&i| Cursor::new(out_bufs[i as usize].get_ref().clone()))
            .collect();
        let mut reconstructed = Vec::new();
        join_stripes(&mut readers, &indices, &mut reconstructed, k, n).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn flipped_bit_detected() {
        let data = vec![0xCDu8; 48];
        let k = 2usize;
        let n = 3usize;
        let stripe = 48;
        let mut out_bufs: Vec<Cursor<Vec<u8>>> = (0..n).map(|_| Cursor::new(Vec::new())).collect();
        split_stripes(Cursor::new(&data), &mut out_bufs, k, n, stripe).unwrap();

        // Flip a bit in share 0 payload region (after header).
        let buf = out_bufs[0].get_mut();
        if let Some(b) = buf.last_mut() {
            *b ^= 0x01;
        }

        let indices = [0u8, 1];
        let mut readers: Vec<Cursor<Vec<u8>>> = indices
            .iter()
            .map(|&i| Cursor::new(out_bufs[i as usize].get_ref().clone()))
            .collect();
        let mut reconstructed = Vec::new();
        let err = join_stripes(&mut readers, &indices, &mut reconstructed, k, n);
        assert!(matches!(err, Err(Error::Integrity)));
        assert!(reconstructed.is_empty());
    }
}
