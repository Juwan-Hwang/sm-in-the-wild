"""GCM (Galois/Counter Mode) over a 128-bit block cipher, written from the
McGrew-Viega specification (NIST submission, 2004; SP 800-38D identical).

Generic: the block cipher is injected as an encryption oracle taking and
returning a 16-byte value. This module contains no SM-specific or AES-specific
code. Calibration lives in tests/test_sm4_gcm_vectors.py:

  * mode logic is validated against the NIST-published AES-GCM worked examples
    (AES_GCM.pdf, Examples #1-#3), using a test-only AES-128;
  * the SM4 composition is validated against RFC 8998 Appendix A.1, the only
    authoritative public SM4-GCM known-answer vector located
    (https://www.rfc-editor.org/rfc/rfc8998.txt).

This is calibration support only: it executes no package code and measures no
package behaviour.
"""

_R = 0xE1000000000000000000000000000000


def _gf_mul(x, y):
    """Multiply x by y in GF(2^128), polynomial x^128+x^7+x^2+x+1,
    GCM bit convention (spec section 3)."""
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (_R if v & 1 else 0)
    return z


def _inc32(block):
    head, ctr = block[:12], int.from_bytes(block[12:], 'big')
    return head + ((ctr + 1) & 0xFFFFFFFF).to_bytes(4, 'big')


def _ghash(h_int, data):
    x = 0
    for off in range(0, len(data), 16):
        x = _gf_mul(x ^ int.from_bytes(data[off:off + 16], 'big'), h_int)
    return x.to_bytes(16, 'big')


def _pad16(s):
    return s + b'\x00' * ((-len(s)) % 16)


def _gctr(enc, icb, data):
    out = bytearray()
    cb = icb
    for off in range(0, len(data), 16):
        cb = _inc32(cb)
        ks = enc(cb)
        blk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks[:len(blk)]))
    return bytes(out)


def _j0(enc, h_int, iv):
    if len(iv) == 12:
        return iv + b'\x00\x00\x00\x01'
    s = _pad16(iv) + (0).to_bytes(8, 'big') + (len(iv) * 8).to_bytes(8, 'big')
    return _ghash(h_int, s)


def gcm_encrypt(enc, key_stream_zero_block, iv, plaintext, aad, tag_len=16):
    """enc: block-encryption oracle (16 bytes -> 16 bytes) under the key.
    key_stream_zero_block: E_K(0^128) (the hash subkey H, as bytes).
    Returns (ciphertext, tag)."""
    h_int = int.from_bytes(key_stream_zero_block, 'big')
    j0 = _j0(enc, h_int, iv)
    c = _gctr(enc, j0, plaintext)
    s_in = _pad16(aad) + _pad16(c) + (len(aad) * 8).to_bytes(8, 'big') + (len(c) * 8).to_bytes(8, 'big')
    s = _ghash(h_int, s_in)
    t = bytes(a ^ b for a, b in zip(s, enc(j0)))
    return c, t[:tag_len]


def gcm_decrypt(enc, key_stream_zero_block, iv, ciphertext, aad, tag):
    """Returns the plaintext, or None if the tag does not verify
    (FAIL in the spec's terms). GHASH input is the ciphertext, per spec."""
    h_int = int.from_bytes(key_stream_zero_block, 'big')
    j0 = _j0(enc, h_int, iv)
    s_in = _pad16(aad) + _pad16(ciphertext) + (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')
    s = _ghash(h_int, s_in)
    t = bytes(a ^ b for a, b in zip(s, enc(j0)))[:len(tag)]
    if t != tag:
        return None
    return _gctr(enc, j0, ciphertext)
