# Reproducibility packet 001: three behaviours of a public npm library (sm-crypto-v2 < 2.0.0)

Public basis only: npm package `sm-crypto-v2`, versions 1.15.1, 1.16.0, 2.0.0 (npm registry); maintainer-published advisory GHSA-v9ww-5g6x-7644 (published 2026-10-28). Nothing here concerns any other package. This is an open invitation to independent reproduction; it is not a review or a validation by itself. CVE: none assigned at time of writing.

## What a reviewer is asked
For each claim, run `repro.js`, then judge on the standards and normal cryptographic practice whether the observed behaviour is (a) a defect that can weaken confidentiality or authenticity, (b) a conformance deviation without a security impact, or (c) acceptable. Give reasons. If you can, answer before reading the advisory, which states the reporter's grading.

## Run
```
mkdir t && cd t && npm init -y && npm install sm-crypto-v2@1.15.1   # then 1.16.0, 2.0.0
node ../repro.js "$PWD"
```
Node 22 was used. The script prints observations only.

## Claims (stated neutrally)
- A. Encrypting with SM4 in CBC or GCM mode without an `iv` option silently uses an all-zero IV (output equals the explicit all-zero-IV output; a different IV gives different output).
- B. Decrypting a tampered SM4-GCM ciphertext without passing a tag returns plaintext instead of failing (control: a tampered ciphertext with the genuine tag is rejected).
- C. `sm2.doSignature(message, privateKey)` with no options does not compute SM3(ZA || message); the signature verifies only without `hash: true` (control: a `hash: true` signature verifies with `hash: true`).

## Observations (run 2026-10-29 05:16 UTC+8, Node 22.23.4, fresh installs)
| check | 1.15.1 | 1.16.0 | 2.0.0 |
|---|---|---|---|
| A cbc no iv == zero iv | true | true | throws "iv is required for cbc mode" |
| A gcm no iv == zero iv | true | true | throws "iv is required for gcm mode" |
| A control (other iv differs) | true | true | true |
| B tampered, no tag | returns plaintext with first byte changed (736576... vs 726576...) | throws, tag required | throws, tag required |
| B control (genuine tag) | rejected | rejected | rejected |
| C default sig verifies with hash:true | false | false | true |
| C default sig verifies by default | true | true | true |
| C control | true | true | true |
Raw outputs: out-1.15.1.json, out-1.16.0.json, out-2.0.0.json.

## Rubric (no verdict supplied)
1. Does the observation hold when you run it? (yes/no per check)
2. Under which standard text or practice is it a problem? Name it (GB/T 32918.2/.5 for C; GB/T 36624 / ISO 19772 / NIST SP 800-38D practice for A and B).
3. Is there a realistic path to harm in an application that uses the default call? Rate none / conformance only / weakens confidentiality or authenticity.
4. What would make you change your mind?

## If you reproduce this
Please say whether you saw the advisory first and whether you have any connection to the reporter or the package. Replies by issue on this repository or by comment on the PREreview page of the preprint (https://prereview.org/preprints/doi-10.5281-zenodo.23716987) are welcome. Only independent replies will be cited as such.
