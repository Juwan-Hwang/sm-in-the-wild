"""Selected existing calibration assertions; source mapping in MANIFEST.json."""
from harness.refimpl import gcm,sm4

def test_sm4_gcm_rfc8998_appendix_a1():
    key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    iv = bytes.fromhex('00001234567800000000ABCD')
    pt = bytes.fromhex(
        'AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD'
        'EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA')
    aad = bytes.fromhex('FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2')
    want_c = bytes.fromhex(
        '17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735'
        'D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D')
    want_t = bytes.fromhex('83DE3541E4C2B58177E065A9BF7B62EC')
    mk = [int.from_bytes(key[4*i:4*i+4], 'big') for i in range(4)]
    rk = sm4.key_schedule(mk)
    enc = lambda blk: sm4.encrypt_block(int.from_bytes(blk, 'big'), rk).to_bytes(16, 'big')
    c, t = gcm.gcm_encrypt(enc, enc(b'\x00' * 16), iv, pt, aad)
    assert c == want_c
    assert t == want_t
    # decryption round-trip + tamper rejection
    assert gcm.gcm_decrypt(enc, enc(b'\x00' * 16), iv, c, aad, t) == pt
    bad = bytearray(t); bad[0] ^= 1
    assert gcm.gcm_decrypt(enc, enc(b'\x00' * 16), iv, c, aad, bytes(bad)) is None
