//! Property tests: SSS roundtrip and k-1 must not recover the secret.

use proptest::prelude::*;
use splitdisk_core::rng::SeededRng;
use splitdisk_core::sss::{combine_session_key, split_session_key, SessionKey};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn sss_any_k_of_n_roundtrip(
        seed in any::<[u8; 32]>(),
        secret_bytes in any::<[u8; 32]>(),
        n in 2usize..=16,
        k_offset in 0usize..15,
    ) {
        let k = 2 + (k_offset % (n - 1)); // 2 <= k <= n
        let mut rng = SeededRng::from_seed(seed);
        let secret = SessionKey::new(secret_bytes);
        let shares = split_session_key(&secret, k, n, &mut rng).unwrap();
        assert_eq!(shares.len(), n);

        // Take first k shares.
        let recovered = combine_session_key(&shares[..k]).unwrap();
        assert!(secret.ct_eq(&recovered));

        // Take last k shares (when n > k).
        if n > k {
            let recovered2 = combine_session_key(&shares[n - k..]).unwrap();
            assert!(secret.ct_eq(&recovered2));
        }

        // k-1 shares must not equal the secret (error or wrong value).
        if k > 2 {
            if let Ok(fake) = combine_session_key(&shares[..(k - 1)]) {
                prop_assert!(!secret.ct_eq(&fake));
            }
        }
    }
}
