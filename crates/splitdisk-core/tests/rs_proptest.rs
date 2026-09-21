//! Property tests: Reed-Solomon any-k-of-n stripe roundtrip.

use proptest::prelude::*;
use splitdisk_core::rs::{join_stripes, split_stripes};
use std::io::Cursor;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn rs_any_k_of_n_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0..400),
        n in 2usize..=8,
        k_offset in 0usize..7,
    ) {
        let k = 2 + (k_offset % (n - 1));
        // stripe_size divisible by k and large enough for a couple stripes.
        let stripe = k * 32;

        let mut out_bufs: Vec<Cursor<Vec<u8>>> =
            (0..n).map(|_| Cursor::new(Vec::new())).collect();
        split_stripes(Cursor::new(&data), &mut out_bufs, k, n, stripe).unwrap();

        // Choose k distinct indices: 0..k
        let indices: Vec<u8> = (0..k as u8).collect();
        let mut readers: Vec<Cursor<Vec<u8>>> = indices
            .iter()
            .map(|&i| Cursor::new(out_bufs[i as usize].get_ref().clone()))
            .collect();
        let mut reconstructed = Vec::new();
        join_stripes(&mut readers, &indices, &mut reconstructed, k, n).unwrap();
        prop_assert_eq!(reconstructed, data);
    }
}
