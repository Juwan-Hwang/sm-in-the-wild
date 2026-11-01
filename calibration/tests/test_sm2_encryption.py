"""Selected existing calibration assertions; source mapping in MANIFEST.json."""
from harness.refimpl.sm2_enc import SM2Curve,GBT32918_4_EXAMPLES

def test_encryption_matches_national_standard_vectors():
    for ex in GBT32918_4_EXAMPLES:
        c = SM2Curve(ex["p"], ex["a"], ex["b"], ex["n"], ex["gx"], ex["gy"])
        pb = c.mul(ex["db"], c.g)
        got = c.encrypt(pb, ex["M"], ex["k"])
        assert got == ex["expected"], f"{ex['name']}: ciphertext mismatch"

def test_decryption_roundtrip_on_standard_vectors():
    for ex in GBT32918_4_EXAMPLES:
        c = SM2Curve(ex["p"], ex["a"], ex["b"], ex["n"], ex["gx"], ex["gy"])
        assert c.decrypt(ex["db"], ex["expected"]) == ex["M"]

def test_standard_mandates_c1c3c2_layout():
    """GB/T 32918.4-2016 A8: C = C1||C3||C2. Hence a ciphertext laid out as
    C1||C2||C3 is NOT merely 'the other order' - it deviates from the standard."""
    ex = GBT32918_4_EXAMPLES[1]
    c = SM2Curve(ex["p"], ex["a"], ex["b"], ex["n"], ex["gx"], ex["gy"])
    c1_len = 1 + 2 * ((ex["p"].bit_length() + 7) // 8)
    ct = ex["expected"]
    c1, c3, c2 = ct[:c1_len], ct[c1_len:c1_len + 32], ct[c1_len + 32:]
    # the standard's C3 is a hash of x2||M||y2, so it must NOT appear where C2
    # would go in a C1||C2||C3 reading of the same bytes
    assert c.decrypt(ex["db"], ct) == ex["M"]                       # C1C3C2 works
    try:
        c.decrypt(ex["db"], c1 + c2 + c3)                           # C1C2C3 must fail
    except Exception:
        return
    raise AssertionError("C1C2C3 ordering unexpectedly decrypted - layout claim wrong")

def test_decrypt_rejects_off_curve_c1():
    """GB/T 32918.4-2016 B1: 验证 C1 是否满足椭圆曲线方程，若不满足则报错并退出.
    This is L6's grade-A source and the SM2 answer to the RustCrypto CVE-2026-22699
    class (invalid-curve .unwrap() panic)."""
    ex = GBT32918_4_EXAMPLES[1]
    c = SM2Curve(ex["p"], ex["a"], ex["b"], ex["n"], ex["gx"], ex["gy"])
    n_len = (ex["p"].bit_length() + 7) // 8
    c1_len = 1 + 2 * n_len
    ct = bytearray(ex["expected"])
    # corrupt C1's x so it leaves the curve, keeping the length and PC byte
    ct[1] ^= 0xFF
    try:
        c.decrypt(ex["db"], bytes(ct))
    except ValueError as e:
        assert "curve" in str(e).lower()
        return
    raise AssertionError("off-curve C1 was silently accepted")
