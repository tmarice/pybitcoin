import pytest
from pybitcoin.ecc import secp256k1, Point, Parity
from hypothesis import given, strategies as st, assume


@given(
    x=st.integers(),
    y=st.integers(),
)
def test_point_rejects_negative_coordinates(x, y):
    '''Point raises ValueError if any coordinate is smaller than 0.'''
    assume(x < 0 or y < 0)
    with pytest.raises(ValueError):
        Point(x, y)


@given(
    a=st.integers(),
    b=st.integers(min_value=secp256k1.p),
)
def test_point_rejects_larger_than_curve_p(a, b):
    '''Point raises ValueError if x or y coordinate is larger than curve's prime.'''
    with pytest.raises(ValueError):
        Point(a, b)

    with pytest.raises(ValueError):
        Point(b, a)


@given(
    x=st.integers(min_value=1, max_value=secp256k1.p - 1),
    y=st.integers(min_value=1, max_value=secp256k1.p - 1),
)
def test_point_rejects_coordinates_not_on_curve(x, y):
    '''Point raises ValueError if coordinates are not on SECP256K1 curve.'''
    assume((pow(y, 2, secp256k1.p) - pow(x, 3, secp256k1.p) - 7 % secp256k1.p) != 0)
    with pytest.raises(ValueError):
        Point(x, y)

@pytest.mark.parametrize('x, y', [
    (0, 0),
    (secp256k1.g_x, secp256k1.g_y),
    (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    (0xF028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A, 0x07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB),
])
def test_point_accepts_coordinates_on_curve(x, y):
    '''Point constructor doesn't raise for valid coordinates on SECP256K1 curve.'''
    Point(x, y)


@pytest.mark.parametrize('x, parity, y', [
    (0x5b134f5d1f47fa961f78cd97720b34fbeb27d21c7879cdf92e0ca8fe75a2892e, Parity.ODD, 0x5fff341efc04b767e279cc142af59a8bfa6d104fd720baff44ede8b10259f27d),
    (0x8a3730423429b7a601c7c273567104d61058c1d95d8efaddf124eaf7f1bf0fe5, Parity.EVEN, 0x37d50fe029b4900de9adca10186de0a7fff7522f926a9a1b746d376a250b8eee),
    (0x74af52b65a853edb9272a6e9ca48fc4dfec8e7a8c6c72b099ab84995f6806da8, Parity.ODD, 0xd2b28e9b2f06dbfba10b36d067a3288886ebcd2cc13725b2ea2e35b9009311e7),
    (0x5d5b514c0466c08adb6f6872b94a300d939d7103c5085985bc3e77d869368cb5, Parity.EVEN, 0xde1f830b0ded3a9e6ede281f0b67a8aa3f80a5ff6cad0c9a43cfac14ea397d32),
])
def test_point_from_x(x, parity, y):
    '''Constructing a point from the x coordinate should respect the given parity and return a point with the valid y'''
    p = Point.from_x(x, parity)

    assert p.y == y

def test_inf():
    '''Return the point at infinity.'''
    inf = Point.inf()

    assert inf.x == inf.y == 0

def test_gen():
    '''Return the generator point of current curve.'''
    gen = Point.gen()

    assert gen.x == Point.curve.g_x and gen.y == Point.curve.g_y
