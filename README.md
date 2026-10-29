# SM in the Wild - preprint companion repository

Companion repository for the preprint "SM in the Wild: Measuring
Security-Semantics Failures in Chinese Commercial Cryptography
Implementations" (prepared for submission to USENIX Security 2027,
Cycle 2; the SEC27 CFP explicitly permits posting a preprint online,
including during the review process).

**Preprint (Zenodo):** [SM in the Wild (v1)](https://doi.org/10.5281/zenodo.23716987)
- version DOI 10.5281/zenodo.23716987; concept DOI (always latest)
10.5281/zenodo.23716986 - archived October 28, 2026, CC-BY-4.0.

## Contents

- `docs/paper.md` - the paper source (Markdown + pandoc).
- `paper/` - the exact build pipeline (`build.sh`, USENIX template, CJK glyph
  fallback) that produces the preprint PDF. Run
  `CJK_FONT=/path/to/NotoSerifCJKsc-Regular.otf bash paper/build.sh` with
  pandoc >= 3.1 and a TeX Live installation; without the CJK font the two
  Chinese-titled references and one code span render as grey placeholder
  boxes and the build says so.
- `calibration/` - the reference-calibration package: from-scratch SM2/SM3/SM4
  reference implementations with published worked-example vector checks.
  Run `python run_checks.py` (Python 3, standard library only): 15 assertions
  pass. The million-iteration SM4 check is opt-in (`--million`).
  See `calibration/SOURCE-NOTICES.md` for the provenance of every constant
  and test vector.

## What is deliberately not here

The empirical research archive (candidate census, adjudication records,
finding evidence, disclosure correspondence) is not part of this repository
at this time. Some of it names third-party packages whose coordinated
disclosure windows are still open; the mapping between the paper's
pseudonyms (U1-U59) and real artefacts is retained privately per the paper's
Ethical Considerations section. Names are restored as disclosure completes,
per the paper's stated policy.

## License

- Code (`calibration/`, `paper/` build scripts): MIT License - see `LICENSE`.
- The paper text (`docs/paper.md`) and the built PDF: Creative Commons
  Attribution 4.0 International (CC-BY-4.0),
  https://creativecommons.org/licenses/by/4.0/.

## Reproducibility packets

- [packet 001: sm-crypto-v2 < 2.0.0, three public behaviours](reproducibility/packet-001-sm-crypto-v2/README.md): neutral rubric and a script for independent reproduction.
