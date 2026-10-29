"""Calibration core extracted from the study reference; recovery helpers omitted."""
M = 0xFFFFFFFF

def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & M

# ---------------------------------------------------------------- SM3
_T_LOW, _T_HIGH = 0x79CC4519, 0x7A879D8A

def _ff(x, y, z, j): return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))
def _gg(x, y, z, j): return (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z))
def _p0(x): return x ^ _rotl(x, 9) ^ _rotl(x, 17)
def _p1(x): return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def sm3(msg: bytes) -> bytes:
    L = len(msg) * 8
    buf = bytearray(msg) + b"\x80"
    while len(buf) % 64 != 56:
        buf += b"\x00"
    buf += L.to_bytes(8, "big")
    V = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
         0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    for off in range(0, len(buf), 64):
        B = buf[off:off + 64]
        W = [int.from_bytes(B[4 * i:4 * i + 4], "big") for i in range(16)]
        for j in range(16, 68):
            W.append(_p1(W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15)) ^ _rotl(W[j - 13], 7) ^ W[j - 6])
        W1 = [W[j] ^ W[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = V
        for j in range(64):
            Tj = _rotl(_T_LOW, j % 32) if j < 16 else _rotl(_T_HIGH, j % 32)
            s1 = _rotl((_rotl(a, 12) + e + Tj) & M, 7)
            s2 = s1 ^ _rotl(a, 12)
            t1 = (_ff(a, b, c, j) + d + s2 + W1[j]) & M
            t2 = (_gg(e, f, g, j) + h + s1 + W[j]) & M
            d, c, b, a = c, _rotl(b, 9), a, t1
            h, g, f, e = g, _rotl(f, 19), e, _p0(t2)
        V = [(V[i] ^ v) & M for i, v in enumerate([a, b, c, d, e, f, g, h])]
    return b"".join(v.to_bytes(4, "big") for v in V)

# ---------------------------------------------------------------- SM2 curve
P  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G  = (GX, GY)

def inv(x, m): return pow(x % m, -1, m)

def padd(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    lam = ((y2 - y1) * inv(x2 - x1, P) % P) if x1 != x2 else ((3 * x1 * x1 + A) * inv(2 * y1, P) % P)
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def pmul(k, p):
    r = None
    while k:
        if k & 1: r = padd(r, p)
        p = padd(p, p); k >>= 1
    return r

def on_curve(pt): return (pt[1] ** 2 - pt[0] ** 3 - A * pt[0] - B) % P == 0

# ---------------------------------------------------------------- SM2 sign/verify
def za(ID: bytes, px: int, py: int) -> bytes:
    """Z_A = SM3(ENTL_A || ID || a || b || Gx || Gy || Px || Py)"""
    entl = (len(ID) * 8).to_bytes(2, "big")
    return sm3(entl + ID + A.to_bytes(32, "big") + B.to_bytes(32, "big")
               + GX.to_bytes(32, "big") + GY.to_bytes(32, "big")
               + px.to_bytes(32, "big") + py.to_bytes(32, "big"))

def sign(msg: bytes, ID: bytes, d: int, k: int):
    """SM2 signature. r = (e + x1) mod n ; s = (1+d)^-1 (k - r d) mod n

    NOTE (ADR-018): r depends on e, so two signatures under the SAME k over different
    messages have DIFFERENT r. The ECDSA 'equal r' nonce-reuse heuristic is invalid here.
    """
    pub = pmul(d, G)
    e = int.from_bytes(sm3(za(ID, pub[0], pub[1]) + msg), "big")
    R = pmul(k, G)
    r = (e + R[0]) % N
    s = (k - r * d) * inv(1 + d, N) % N
    return r, s, pub

def verify(msg: bytes, ID: bytes, r: int, s: int, pub) -> bool:
    if not (1 <= r < N and 1 <= s < N): return False
    e = int.from_bytes(sm3(za(ID, pub[0], pub[1]) + msg), "big")
    # s(1+d) = k - r*d  =>  k = s + d(s+r)  =>  kG = s*G + (s+r)*P
    R = padd(pmul(s, G), pmul((s + r) % N, pub))
    return R is not None and (e + R[0]) % N == r

