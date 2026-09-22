# Vendoring Record

This file is the audit trail for every third-party binary/source component
built into a SplitDisk boot image. Nothing in this file was fetched or
verified by an AI agent — every entry was cloned, GPG-verified, and
recorded by a human, by hand, outside the sandboxed build environment. This
is intentional: the whole point of pinning these components is that no
automated process, including this project's own tooling, is trusted to
make the verification judgment.

Do not add an entry to this file, or edit an existing one, without a human
directly supplying the values — do not fetch, guess, or "help" by filling
in a plausible-looking value.

`vendor/grub/`, `vendor/linux/`, `vendor/ccid/`, and `vendor/gnulib/` are
local git checkouts cloned from the independently verified upstream trees
(not `git archive` exports). Keeping `.git` metadata is intentional so
`git rev-parse HEAD` can confirm each tree matches the pinned commit below —
an earlier archive-based layout stripped that metadata and made the check
impossible.

---

## GRUB

- **Upstream repo:** git://git.savannah.gnu.org/grub.git
  (fetched via https://git.savannah.gnu.org/git/grub.git, redirected by the
  server to https://https.git.savannah.gnu.org/git/grub.git/)
- **Pinned tag:** grub-2.14
- **Tag object hash:** d34223e9885c5b5803b029ddabada3e60711754c
- **Pinned commit hash:** d38d6a1a9b79427848976f53d474392cd29c2a71
- **Tagger:** Daniel Kiper <daniel.kiper@oracle.com>
- **Signing key fingerprint:** BE5C 2320 9ACD DACE B20D B0A2 8C81 89F1 988C
  2166
- **Fingerprint cross-checked against three independent sources, all
  agreeing:**
  - Debian's grub2 packaging (debian/upstream/signing-key.asc, package
    version 2.14-3)
  - keys.openpgp.org (verified-email keyserver), by-email lookup for
    daniel.kiper@oracle.com
  - The grub-devel mailing list release announcement for GRUB 2.14
    (lists.gnu.org/archive/html/grub-devel/2026-01/msg00029.html), which
    states the fingerprint directly in the announcement body
  - (Savannah's own GRUB project page and gnu.org's GRUB pages were also
    checked and did NOT publish a fingerprint — noted for completeness,
    not a discrepancy)
- **git verify-tag output (verbatim):**

```
gpg: key 8C8189F1988C2166: public key "Daniel Kiper dkiper@net-space.pl" imported
pub rsa4096 2017-02-05 [SC] [expires: 2029-04-24]
BE5C23209ACDDACEB20DB0A28C8189F1988C2166
uid [ unknown] Daniel Kiper dkiper@net-space.pl
uid [ unknown] Daniel Kiper daniel.kiper@oracle.com
sub rsa4096 2017-02-05 [E] [expires: 2029-04-24]
gpg: Signature made Wed 14 Jan 2026 04:53:00 PM CET
gpg: using RSA key BE5C23209ACDDACEB20DB0A28C8189F1988C2166
gpg: Good signature from "Daniel Kiper dkiper@net-space.pl" [unknown]
gpg: aka "Daniel Kiper daniel.kiper@oracle.com" [unknown]
gpg: WARNING: This key is not certified with a trusted signature.
gpg: There is no indication that the signature belongs to the owner.
Primary key fingerprint: BE5C 2320 9ACD DACE B20D B0A2 8C81 89F1 988C 2166
```

  (Original output was in Norwegian; translated here for readability —
  meaning unchanged. The "not certified with a trusted signature" warning
  is GPG's web-of-trust notice, expected for any key not personally signed
  by the verifier; it does not indicate the signature itself is invalid.
  It is superseded here by the three-source fingerprint cross-check above.)
- **Date verified:** 2026-09-22
- **Verified by:** Supermagnum
- **Vendored as:** vendor/grub/ (to be populated when the human performs the
  actual git archive/clone-and-pin step; not yet done as of this record)
- **Known issues at this pin:** GRUB 2.12's official release tarball was
  missing grub-core/extra_deps.lst (fixed upstream in git, never
  re-released in the tarball). Building from this pinned git commit
  (rather than the release tarball) sidesteps that issue entirely.

---

## Linux kernel

- **Upstream repo:**
  git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
- **Pinned tag:** v6.12.111
- **Tag object hash:** b819bf73ee69da09487c3defe5e11a5365452d9d
- **Pinned commit hash:** e2acc2211022246c77740d5df08265cc27eedcc5
- **Tagger:** Greg Kroah-Hartman <gregkh@linuxfoundation.org>
- **Signing key fingerprint:** 647F 2865 4894 E3BD 4571 99BE 38DB BDC8
  6092 693E
- **Fingerprint cross-checked against three independent sources, all
  agreeing:**
  - kernel.org's own published signature page
    (https://www.kernel.org/signature.html)
  - Debian's linux packaging (debian/upstream/signing-key.asc, package
    version 6.12.94-1 — a nearby but not identical point release; the key
    itself is the stable-tree signing key used across point releases, not
    specific to one)
  - kernel.org's own Web-of-Trust page
    (https://www.kernel.org/doc/wot/gregkh.html)
  - (keys.openpgp.org returned no key for the email addresses tried;
    noted for completeness — absence there is not a discrepancy, since
    that keyserver only lists addresses with confirmed opt-in)
- **Key import note:** the default keyserver pool (initial `gpg
  --recv-keys` attempt) returned a stripped key with no user ID attached
  and failed ("new key but contains no user ID - skipped" / "No public
  key" on first verify attempt) — a known issue with the aging SKS
  keyserver network, not an issue with the fingerprint or the tag. Resolved
  by importing via Web Key Directory (WKD) instead:
  `gpg --auto-key-locate wkd --locate-keys gregkh@kernel.org`, which
  fetches the key directly from kernel.org's own HTTPS infrastructure
  rather than a shared keyserver pool, and is in fact kernel.org's own
  recommended lookup method.
- **git verify-tag output (verbatim):**

```
gpg: Signature made Mon 21 Sep 2026 03:02:00 PM CEST
gpg: using RSA key 647F28654894E3BD457199BE38DBBDC86092693E
gpg: Good signature from "Greg Kroah-Hartman gregkh@kernel.org" [unknown]
gpg: WARNING: This key is not certified with a trusted signature.
gpg: There is no indication that the signature belongs to the owner.
Primary key fingerprint: 647F 2865 4894 E3BD 4571 99BE 38DB BDC8 6092 693E
```

  (Translated from Norwegian original; meaning unchanged. Same web-of-trust
  caveat as above applies and is superseded by the three-source check.)
- **Date verified:** 2026-09-22
- **Verified by:** Supermagnum
- **Vendored as:** vendor/linux/ (not yet populated as of this record)
- **Kernel config basis:** minimal defconfig + SPEC §10.5 additions (to be
  documented separately when the kernel build integration work happens)

---

## CCID driver

- **Upstream repo:** https://github.com/LudovicRousseau/CCID
  (release tarballs and .asc signatures also published at
  https://ccid.apdu.fr/files/)
- **Pinned tag:** 1.8.4
- **Tag object hash:** 4a65fffc6d64399db3003ed4599d9ba029775026
- **Pinned commit hash:** c37cf6cb42279ce9648ff7314180c866d68f9e0d
- **Tagger:** Ludovic Rousseau <ludovic.rousseau@free.fr>
- **Signing key fingerprint:** F5E1 1B9F FE91 1146 F41D 953D 78A1 B4DF E8F9
  C57E
- **Fingerprint cross-checked against four independent sources, all
  agreeing this key (not Rousseau's other published key, ending
  ...CCF072ED09712A89) is the one used to sign CCID releases:**
  - Ludovic Rousseau's own personal site (http://ludovic.rousseau.free.fr/,
    file gpg_key_E8F9C57E.txt) — noted as fetched over plain HTTP, not
    HTTPS, so treated as corroborating rather than independently
    authoritative on its own
  - Gentoo's sec-keys package for this developer
    (sec-keys/openpgp-keys-ludovicrousseau ebuild,
    SEC_KEYS_VALIDPGPKEYS entry)
  - Debian's ccid packaging (debian/upstream/signing-key.asc, package
    version 1.8.4-1)
  - keys.openpgp.org, by-email lookup for rousseau@debian.org (note: the
    same lookup for ludovic.rousseau@free.fr returned Rousseau's OTHER
    key instead — not a discrepancy, just that keyserver's per-address
    listing, since the signature's own issuer field and the other three
    sources all point to this fingerprint for the CCID releases
    specifically)
- **Two artifacts independently verified with this key, both clean:**
  1. Git tag signature:

```
gpg: Signature made Sun 20 Sep 2026 03:29:00 PM CEST
gpg:                using RSA key F5E11B9FFE911146F41D953D78A1B4DFE8F9C57E
gpg: Good signature from "Ludovic Rousseau <rousseau@debian.org>" [unknown]
gpg: Signature notation: manu=2,2.5+1.12,0,3
gpg: WARNING: This key is not certified with a trusted signature.
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: F5E1 1B9F FE91 1146 F41D  953D 78A1 B4DF E8F9 C57E
```

  2. Release tarball signature (ccid-1.8.4.tar.xz against
     ccid-1.8.4.tar.xz.asc, downloaded from https://ccid.apdu.fr/files/):

```
gpg: Signature made Sun 20 Sep 2026 03:19:00 PM CEST
gpg:                using RSA key F5E11B9FFE911146F41D953D78A1B4DFE8F9C57E
gpg: Good signature from "Ludovic Rousseau <rousseau@debian.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature.
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: F5E1 1B9F FE91 1146 F41D  953D 78A1 B4DF E8F9 C57E
```

  (Both translated from Norwegian originals; meaning unchanged. Same
  web-of-trust caveat as the GRUB and kernel entries applies and is
  superseded by the four-source fingerprint cross-check above.)
- **Date verified:** 2026-09-22
- **Verified by:** Supermagnum
- **Vendored as:** vendor/ccid/ (not yet populated as of this record)
- **Known issues at this pin:** none identified. Note that Rousseau
  publishes a second PGP key (fingerprint ending ...CCF072ED09712A89,
  rsa3072, expired 2024-11-10 per one source) which is NOT the key used
  for these CCID release signatures — do not confuse the two if this
  project is re-verified in the future.

---

## gnulib

- **Upstream repo:** https://git.savannah.gnu.org/git/gnulib.git
- **Pinned commit hash:** 9f48fb992a3d7e96610c4ce8be969cff2d61a01b
- **Why this exact revision:** required by vendor/grub's own
  bootstrap.conf (part of the already-verified, signed grub-2.14 release,
  commit d38d6a1a9b79427848976f53d474392cd29c2a71) — not an independently
  chosen dependency; GRUB's own verified source specifies it.
- **Verification model (different from GRUB/Linux/CCID):** gnulib has no
  PGP-signed releases; it is a rolling, commit-pinned shared library.
  Trust rests on two things: (1) the requested commit hash is drawn from
  GRUB's already-verified signed source, not chosen independently, and
  (2) the content at that commit hash was cross-checked across two
  independently-hosted mirrors.
- **Cross-check performed:** cloned from both
  https://git.savannah.gnu.org/git/gnulib.git and
  https://github.com/coreutils/gnulib.git, checked out
  9f48fb992a3d7e96610c4ce8be969cff2d61a01b in each, and ran
  `diff -rq` between the two working trees. Result: every reported
  difference was confined to .git-internal bookkeeping (remote config,
  reflogs, and each host's own pack file naming) — zero differences in
  any tracked source file. Full diff output recorded below for the
  audit trail:

```
Files gnulib/.git/config and gnulib-mirror-check/.git/config differ
Files gnulib/.git/index and gnulib-mirror-check/.git/index differ
Files gnulib/.git/logs/HEAD and gnulib-mirror-check/.git/logs/HEAD differ
Files gnulib/.git/logs/refs/heads/master and gnulib-mirror-check/.git/logs/refs/heads/master differ
Files gnulib/.git/logs/refs/remotes/origin/HEAD and gnulib-mirror-check/.git/logs/refs/remotes/origin/HEAD differ
Only in gnulib-mirror-check/.git/objects/pack: pack-87643eff3449b0fdd0d12c09654961ee9f41d432.{idx,pack,rev}
Only in gnulib/.git/objects/pack: pack-c28aa79afbf2e65d4418743f4679b075a5619ed9.{idx,pack,rev}
```

  (Translated from Norwegian original; meaning unchanged.)
- **Vendored as:** vendor/gnulib/ (git checkout, .git preserved, same
  pattern as GRUB/Linux/CCID, so rev-parse HEAD can confirm the pin
  going forward)
- **Date verified:** 2026-09-22
- **Verified by:** Supermagnum

---

## Re-verification policy

Re-verify (repeat the cross-check, don't just trust this file) if:

- Any pin above is bumped to a new version.
- More than 12 months have passed since "Date verified" (keys can be
  revoked or compromised after the fact; a signature valid at the time of
  checking doesn't guarantee the key wasn't later compromised in a way
  that matters for a long-lived project).
- This file's own git history shows an edit that wasn't made by the
  documented human verifier.
