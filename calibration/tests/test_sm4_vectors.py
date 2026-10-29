"""Selected existing calibration assertions; source mapping in MANIFEST.json."""
from harness.refimpl.sm4 import encrypt_block, decrypt_block, key_schedule

KEY = int("0123456789ABCDEFFEDCBA9876543210", 16)

PT = int("0123456789ABCDEFFEDCBA9876543210", 16)

STD_RK = [
    0xF12186F9, 0x41662B61, 0x5A6AB19A, 0x7BA92077, 0x367360F4, 0x776A0C61,
    0xB6BB89B3, 0x24763151, 0xA520307C, 0xB7584DBD, 0xC30753ED, 0x7EE55B57,
    0x6988608C, 0x30D895B7, 0x44BA14AF, 0x104495A1, 0xD120B428, 0x73B55FA3,
    0xCC874966, 0x92244439, 0xE89E641F, 0x98CA015A, 0xC7159060, 0x99E1FD2E,
    0xB79BD80C, 0x1D2115B0, 0x0E228AEB, 0xF1780C81, 0x428D3654, 0x62293496,
    0x01CF72E5, 0x9124A012]

RK = key_schedule([(KEY >> 96) & 0xFFFFFFFF, (KEY >> 64) & 0xFFFFFFFF,
                   (KEY >> 32) & 0xFFFFFFFF, KEY & 0xFFFFFFFF])

def test_round_keys_match_gbt32907_appendix_a():
    assert RK == STD_RK, "32 round keys do not reproduce the standard"

def test_ciphertext_example1():
    got = encrypt_block(PT, RK)
    assert got == 0x681EDF34D206965E86B3E94F536E4246

def test_roundtrip():
    ct = encrypt_block(PT, RK)
    assert decrypt_block(ct, RK) == PT

def test_example2_million_iterations():
    cur = PT
    for _ in range(1_000_000):
        cur = encrypt_block(cur, RK)
    assert cur == 0x595298C7C6FD271F0402F804C33D3F66

def test_first_round_state():
    x = [(PT >> 96) & 0xFFFFFFFF, (PT >> 64) & 0xFFFFFFFF,
         (PT >> 32) & 0xFFFFFFFF, PT & 0xFFFFFFFF]
    from harness.refimpl.sm4 import _t
    x.append(x[0] ^ _t(x[1] ^ x[2] ^ x[3] ^ RK[0]))
    assert x[4] == 0x27FAD345
