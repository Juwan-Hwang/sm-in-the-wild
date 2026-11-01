"""Selected existing calibration assertions; source mapping in MANIFEST.json."""
from harness.refimpl.sm import sm3

GBT32905_SM3_VECTORS = [
    (bytes.fromhex("616263"),
     "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    (bytes.fromhex("61626364" * 16),                     # A.2 512-bit message
     "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
]

def test_sm3_matches_national_standard_vectors():
    """GB/T 32905-2016 附录 A.1 / A.2. This is our only A-grade correctness anchor."""
    for msg, expected in GBT32905_SM3_VECTORS:
        assert sm3(msg).hex() == expected
