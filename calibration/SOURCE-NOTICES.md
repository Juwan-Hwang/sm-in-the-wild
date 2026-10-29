# Sources and notices

This is a source ledger. Original code in this package is released under the repository's MIT License (see `../LICENSE`); third-party material retains its own terms as listed below.

Author-reported origin (2026-10-27): the oracle reference implementation and calibration tests were written by AI from GB standards. This supersedes the author's immediately preceding tentative "we probably wrote it from GB" explanation. SM2/SM3/SM4 comments are consistent with that account. The generic GCM file separately says it was written from the McGrew-Viega specification (NIST submission, 2004; SP 800-38D); its RFC vector is attributed below. Do not describe every file or vector as originating in GB. This record does not independently prove no copied expression exists, and does not invent another contributor or require an originality certificate.

- SM3 numeric fixtures: GB/T 32905-2016 Appendix A.1/A.2.
- SM4 algorithm constants and numeric fixtures: GB/T 32907-2016 Appendix A.
- SM2 numeric fixtures: GB/T 32918.4-2016 Appendix A and GB/T 32918.5-2017 clause 6/Appendix A. Full standards PDFs/text dumps are not included. Numeric interoperability examples are distinguished from copying whole copyrighted documents; no blanket standards redistribution license is asserted.
- SM4-GCM numeric fixture: RFC 8998, Appendix A.1, P. Yang, March 2021, https://www.rfc-editor.org/rfc/rfc8998.txt . Copyright (c) 2021 IETF Trust and the persons identified as the document authors. All rights reserved. The RFC is an Independent Submission, not an IETF Standards Track document. RFC 5744 permits extraction/adaptation of default Independent Submission material with suitable attribution unless the source specifies no derivatives; the fetched RFC 8998 contains no no-derivatives legend. Do not relabel it generically as BSD without regard to its stream. Source terms: https://www.rfc-editor.org/rfc/rfc5744.txt and https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/ .

The tiny earlier candidate additionally used NIST AES-GCM examples 1-3 and a test-only AES helper described as borrowed without a named implementation source. This broader candidate omits that helper rather than supplying an invented attribution. NIST's official licensing policy is https://www.nist.gov/open/license ; its publication/data permissions are not a license for unrelated implementations.
