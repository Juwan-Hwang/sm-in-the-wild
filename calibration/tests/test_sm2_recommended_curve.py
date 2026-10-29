"""Selected existing calibration assertions; source mapping in MANIFEST.json."""
from harness.refimpl.sm import P,A,B,N,GX,GY,pmul,za,sm3,inv,sign as sm_sign,verify as sm_verify
from harness.refimpl.sm2_enc import SM2Curve,kdf

STD_P  = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"

STD_A  = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"

STD_B  = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"

STD_N  = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

STD_GX = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"

STD_GY = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

ID_A = "31323334353637383132333435363738"

ENTL_A = "0080"

M_SIG = "6D65737361676520646967657374"

D_A = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"

X_A = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"

Y_A = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"

Z_A = "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3"

E   = "F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640"

K   = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"

X_1 = "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73"

Y_1 = "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0"

R   = "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"

S   = "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"

M_ENC = "656E6372797074696F6E207374616E64617264"

X_2 = "335E18D751E51F040E27D468138B7AB1DC86AD7F981D7D416222FD6AB3ED230D"

Y_2 = "AB743EBCFB22D64F7B6AB791F70658F25B48FA93E54064FDBFBED3F0BD847AC9"

T_ENC = "44E60FDBF0BAE81437665374BEF26749046C9E"

C_2 = "21886CA989CA9C7D58087307CA93092D651EFA"

C_3 = "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766"

def test_curve_parameters_match_the_standard():
    assert P == int(STD_P, 16)
    assert A == int(STD_A, 16)
    assert B == int(STD_B, 16)
    assert N == int(STD_N, 16)
    assert GX == int(STD_GX, 16)
    assert GY == int(STD_GY, 16)

def test_signature_worked_example_on_the_real_curve():
    ID = bytes.fromhex(ID_A)
    msg = bytes.fromhex(M_SIG)
    dA, k = int(D_A, 16), int(K, 16)
    xA, yA = int(X_A, 16), int(Y_A, 16)

    assert pmul(dA, (int(STD_GX, 16), int(STD_GY, 16))) == (xA, yA)   # [dA]G
    assert pmul(k, (int(STD_GX, 16), int(STD_GY, 16))) == (int(X_1, 16), int(Y_1, 16))

    # Z_A with the DEFAULT user ID - the M3 anchor
    assert za(ID, xA, yA).hex().upper() == Z_A

    e = int.from_bytes(sm3(za(ID, xA, yA) + msg), "big")
    assert e == int(E, 16)

    r, s, _ = sm_sign(msg, ID, dA, k)
    assert format(r, "064X") == R
    assert format(s, "064X") == S

    # and the published signature verifies
    assert sm_verify(msg, ID, int(R, 16), int(S, 16), (xA, yA))

def test_encryption_worked_example_on_the_real_curve():
    c = SM2Curve(P, A, B, N, GX, GY)
    pb = (int(X_A, 16), int(Y_A, 16))
    k = int(K, 16)
    msg = bytes.fromhex(M_ENC)

    assert pmul(k, pb) == (int(X_2, 16), int(Y_2, 16))                # [k]PA
    t = kdf(bytes.fromhex(X_2) + bytes.fromhex(Y_2), 152)
    assert t.hex().upper() == T_ENC
    c2 = bytes(m ^ t[i] for i, m in enumerate(msg))
    assert c2.hex().upper() == C_2
    c3 = sm3(bytes.fromhex(X_2) + msg + bytes.fromhex(Y_2))
    assert c3.hex().upper() == C_3

def test_ciphertext_layout_is_c1_c3_c2():
    """The standard's own output line:  C = C1||C3||C2, printed as
    04||X1||Y1||C3||C2. Fourth independent corroboration of the layout."""
    c = SM2Curve(P, A, B, N, GX, GY)
    c1 = bytes.fromhex("04" + X_1 + Y_1)                              # PC=04 || x || y
    ct = c1 + bytes.fromhex(C_3) + bytes.fromhex(C_2)
    assert len(ct) == 1 + 32 + 32 + 32 + 19
    assert c.decrypt(int(D_A, 16), ct) == bytes.fromhex(M_ENC)

def test_c1c2c3_relayout_of_the_same_bytes_fails():
    """Negative control: the identical bytes read as C1||C2||C3 must fail."""
    c = SM2Curve(P, A, B, N, GX, GY)
    c1 = bytes.fromhex("04" + X_1 + Y_1)
    wrong = c1 + bytes.fromhex(C_2) + bytes.fromhex(C_3)
    try:
        c.decrypt(int(D_A, 16), wrong)
    except Exception:
        return
    raise AssertionError("C1||C2||C3 layout unexpectedly decrypted - layout claim is wrong")
