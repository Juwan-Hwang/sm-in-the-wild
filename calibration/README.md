# Reference calibration

This package separates useful existing calibration checks from the study corpus. From this directory, run `python run_checks.py` with Python 3 and no other dependencies. `python run_checks.py --million` also runs the existing expensive SM4 million-iteration check.

The default runner passed 15 existing assertion functions locally. It does not execute the opt-in million-iteration check. No pytest success or complete-suite success is claimed. This is packaging and rerunning existing calibration, not a new empirical experiment.

## What it supports

- SM3: both published GB/T 32905-2016 Appendix A message/digest examples (one assertion function).
- SM2: recommended-curve parameters, identity-bound signature example, encryption/KDF/digest steps and ciphertext layout from GB/T 32918.5-2017; two GB/T 32918.4-2016 encryption examples, round trips, layout rejection and off-curve rejection.
- SM4: GB/T 32907-2016 round keys, first-round state, single-block output and round trip. Million-iteration assertion included but not rerun by default.
- SM4-GCM: RFC 8998 A.1 output, round trip and tag-tamper rejection (one assertion function). The AES helper of uncertain upstream attribution is not included, so this package does not claim the three independent AES-GCM mode-logic anchors.

The source manifest records exact originals, original hashes, output hashes and extraction changes. Retained executable bodies are unchanged. Source quotations and project/recovery discussion were removed where not needed. The general SM2 recovery helpers, project probes, target packages, corpus records, full standards documents, JDK-derived P-256 data and third-party dependencies are omitted.

## What it does not support

No SM2 key exchange reference exists here. Passing example vectors is not complete implementation correctness, independent scientific review, a production cryptographic library, or replay of any finding. The package does not reproduce the census, 141/145 replay support, F-0032 grouping, detector comparison, 88 seeded defects or whole-paper claims. Published example keys are standard test fixtures, not project credentials.

The full standards-text traceability assertion is deliberately not included: it depends on redistributed standard text, which this package does not contain. Omitting it is not a successful traceability check. Existing complete-suite results remain attached to their original repository version, not this package.

## Distribution

Released publicly with this repository under the MIT License (see `../LICENSE`). On 2026-10-27 the author clarified that the oracle reference implementation and calibration tests were written by AI from GB standards. This is the author's reported source, consistent with the SM2/SM3/SM4 source comments; it is not a verified absence-of-copying claim. The GCM helper separately names the McGrew-Viega/NIST specification, and its composition fixture is from RFC 8998, not GB. The previously unattributed AES helper remains excluded. No actual third-party code-copy attribution has been identified in the retained subset. See SOURCE-NOTICES.md.
