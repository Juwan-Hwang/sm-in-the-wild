"""SM2 encryption calibration code; standard numeric examples are retained."""
from .sm import sm3, padd, pmul, inv, on_curve

def kdf(Z: bytes, klen_bits: int) -> bytes:
    """GB/T 32918.4-2016 §5.4.3. Note the counter starts at 0x00000001 and is
    big-endian 32-bit."""
    v = 256
    klen = (klen_bits + 7) // 8
    ct = 1
    out = bytearray()
    while len(out) < klen:
        out += sm3(Z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])

class SM2Curve:
    """A curve instance, so we can run the standard's worked examples."""
    def __init__(self, p, a, b, n, gx, gy, h=1):
        self.p, self.a, self.b, self.n, self.g, self.h = p, a, b, n, (gx, gy), h

    def _padd(self, p1, p2):
        """Curve-local point addition (sm.py's helpers are pinned to the SM2 curve)."""
        if p1 is None: return p2
        if p2 is None: return p1
        (x1, y1), (x2, y2) = p1, p2
        P, A = self.p, self.a
        if x1 == x2 and (y1 + y2) % P == 0: return None
        lam = ((y2 - y1) * inv(x2 - x1, P) % P) if x1 != x2 else ((3 * x1 * x1 + A) * inv(2 * y1, P) % P)
        x3 = (lam * lam - x1 - x2) % P
        return (x3, (lam * (x1 - x3) - y1) % P)

    def _pmul(self, k, p):
        r = None
        while k:
            if k & 1: r = self._padd(r, p)
            p = self._padd(p, p); k >>= 1
        return r

    def _point_to_bytes(self, pt):
        x, y = pt
        n = (self.p.bit_length() + 7) // 8
        return b"\x04" + x.to_bytes(n, "big") + y.to_bytes(n, "big")

    def _bytes_to_point(self, b):
        if not b or b[0] != 0x04:
            raise ValueError("C1 must be uncompressed (PC=04)")
        n = (self.p.bit_length() + 7) // 8
        if len(b) != 1 + 2 * n:
            raise ValueError("bad C1 length")
        x = int.from_bytes(b[1:1 + n], "big")
        y = int.from_bytes(b[1 + n:1 + 2 * n], "big")
        if not self._on_curve((x, y)):
            raise ValueError("C1 is not on the curve")
        return (x, y)

    def _on_curve(self, pt):
        return (pt[1] ** 2 - pt[0] ** 3 - self.a * pt[0] - self.b) % self.p == 0

    def sm2_sign(self, msg: bytes, ID: bytes, d: int, k: int):
        """SM2 signature (GB/T 32918.2-2016 §6) on *this* curve.

        Parameterised on the curve so the same code can check a signature a library
        produced on the WRONG curve. sm.py's module-level sign() is pinned to the
        standard SM2 curve and cannot do that.
        """
        pub = self._pmul(d, self.g)
        z = self._z_a(ID, pub)
        e = int.from_bytes(sm3(z + msg), "big")
        R = self._pmul(k, self.g)
        r = (e + R[0]) % self.n
        s = (k - r * d) * inv(1 + d, self.n) % self.n
        return r, s, pub

    def sm2_verify(self, msg: bytes, ID: bytes, r: int, s: int, pub) -> bool:
        """§7. s(1+d) = k - r*d  =>  k = s + d(s+r)  =>  kG = s*G + (s+r)*P."""
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        z = self._z_a(ID, pub)
        e = int.from_bytes(sm3(z + msg), "big")
        R = self._padd(self._pmul(s, self.g), self._pmul((s + r) % self.n, pub))
        return R is not None and (e + R[0]) % self.n == r

    def _z_a(self, ID: bytes, pub) -> bytes:
        n = (self.p.bit_length() + 7) // 8
        return sm3((len(ID) * 8).to_bytes(2, "big") + ID
                   + self.a.to_bytes(n, "big") + self.b.to_bytes(n, "big")
                   + self.g[0].to_bytes(n, "big") + self.g[1].to_bytes(n, "big")
                   + pub[0].to_bytes(n, "big") + pub[1].to_bytes(n, "big"))

    def _x2y2_octets(self, pt):
        """Coordinates as octet strings of the field element length
        (GB/T 32918.1 §4.2.6/4.2.5). For Fp-192 this is 24 bytes, not 32."""
        n = (self.p.bit_length() + 7) // 8
        return pt[0].to_bytes(n, "big"), pt[1].to_bytes(n, "big")

    def mul(self, k, pt):
        """Curve-local scalar multiplication. Use this, NOT sm.pmul - the latter
        is pinned to the SM2 curve and silently gives wrong answers on the
        Fp-192 / Fp-256 curves used by GB/T 32918.4-2016 附录 A."""
        return self._pmul(k, pt)

    def encrypt(self, pb, msg: bytes, k: int):
        """§6.1 A1-A8. `k` is injectable so tests can replay the standard's vectors."""
        klen = len(msg) * 8
        C1 = self._point_to_bytes(self._pmul(k, self.g))
        S = self._pmul(self.h, pb)
        if S is None:
            raise ValueError("S is the point at infinity")
        x2, y2 = self._pmul(k, pb)
        xo, yo = self._x2y2_octets((x2, y2))
        t = kdf(xo + yo, klen)
        if t == b"\x00" * klen:
            raise ValueError("t is all-zero; retry with a new k")
        C2 = bytes(m ^ t[i] for i, m in enumerate(msg))
        C3 = sm3(xo + msg + yo)
        return C1 + C3 + C2

    def decrypt(self, db, ciphertext: bytes):
        """§7.1 B1-B7."""
        n_len = (self.p.bit_length() + 7) // 8
        c1_len = 1 + 2 * n_len
        C1b, rest = ciphertext[:c1_len], ciphertext[c1_len:]
        C3, C2 = rest[:32], rest[32:]
        C1 = self._bytes_to_point(C1b)
        S = self._pmul(self.h, C1)
        if S is None:
            raise ValueError("S is the point at infinity")
        x2, y2 = self._pmul(db, C1)
        xo, yo = self._x2y2_octets((x2, y2))
        t = kdf(xo + yo, len(C2) * 8)
        if t == b"\x00" * len(C2):
            raise ValueError("t is all-zero")
        M = bytes(c ^ t[i] for i, c in enumerate(C2))
        u = sm3(xo + M + yo)
        if u != C3:
            raise ValueError("C3 mismatch")
        return M

# ---------------------------------------------------------------------------
# GB/T 32918.4-2016 附录 A 资料性附录 - worked examples (verbatim from refs/)
# ---------------------------------------------------------------------------
GBT32918_4_EXAMPLES = [
    dict(
        name="A.2 示例1 Fp-192",
        p=0xBDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F,
        a=0xBB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985,
        b=0x1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1,
        n=0xBDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677,
        gx=0x4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640,
        gy=0x02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2,
        M=bytes.fromhex("656E6372797074696F6E207374616E64617264"),
        db=0x58892B807074F53FBF67288A1DFAA1AC313455FE60355AFD,
        k=0x384F30353073AEECE7A1654330A96204D37982A3E15B2CB5,
        expected=bytes.fromhex(
            "04"
            "23FC680B124294DFDF34DBE76E0C38D883DE4D41FA0D4CF5"
            "70CF14F20DAF0C4D777F738D16B16824D31EEFB9DE31EE1F"
            "6AFB3BCEBD76F82B252CE5EB25B5799686902B8CF2FD8753"
            "6E55EF7603B09E7C"
            "610567DBD4854F51F4F00ADCC01CFE90B1FB1C"),
    ),
    dict(
        name="A.2 示例2 Fp-256",
        p=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
        a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
        b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
        n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
        gx=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
        gy=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2,
        M=bytes.fromhex("656E6372797074696F6E207374616E64617264"),
        db=0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0,
        k=0x4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F,
        expected=bytes.fromhex(
            "04"
            "245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E7"
            "76CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8"
            "9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E0748"
            "0653426D"
            "650053A89B41C418B0C3AAD00D886C00286467"),
    ),
]
