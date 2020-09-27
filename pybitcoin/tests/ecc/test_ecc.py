import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from pybitcoin.ecc import Parity, Point, secp256k1
from pybitcoin.tests.ecc.fixtures import ADD_POINTS, MUL_POINTS, POINTS


@given(
    a=st.integers(max_value=-1),
    b=st.integers(),
)
def test_point_rejects_negative_coordinates(a, b):
    '''Point raises ValueError if any coordinate is smaller than 0.'''
    with pytest.raises(ValueError):
        Point(a, b)

    with pytest.raises(ValueError):
        Point(b, a)


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


@given(coords=st.sampled_from(POINTS))
def test_point_accepts_coordinates_on_curve(coords):
    '''Point constructor doesn't raise for valid coordinates on SECP256K1 curve.'''
    Point(*coords)


@given(coords=st.sampled_from(POINTS))
def test_point_from_x(coords):
    '''Constructing a point from the x coordinate should respect the given parity and return a point with the valid y'''
    assume(coords != (0, 0))

    x, y = coords

    assert Point.from_x(x, Parity(y & 1)).y == y
    assert Point.from_x(x, Parity(1 - y & 1)).y == secp256k1.p - y


def test_inf():
    '''Return the point at infinity.'''
    inf = Point.inf()

    assert inf.x == inf.y == 0


def test_gen():
    '''Return the generator point of current curve.'''
    gen = Point.gen()

    assert gen.x == Point.curve.g_x and gen.y == Point.curve.g_y


@given(coords_1=st.sampled_from(POINTS), coords_2=st.sampled_from(POINTS))
def test_point_eq(coords_1, coords_2):
    assume(coords_1 != coords_2)

    assert Point(*coords_1) == Point(*coords_1)
    assert Point(*coords_2) == Point(*coords_2)
    assert Point(*coords_1) != Point(*coords_2)


@given(coords=st.sampled_from(POINTS))
def test_add_infinity(coords):
    p = Point(*coords)
    inf = Point.inf()

    assert p + inf == inf + p == p


@given(data=st.sampled_from(ADD_POINTS))
def test_add(data):
    coords_1, coords_2, coords_res = data
    p1 = Point(*coords_1)
    p2 = Point(*coords_2)

    assert p1 + p2 == Point(*coords_res)


@given(coords=st.sampled_from(POINTS))
def test_neg(coords):
    assume(coords != (0, 0))

    p = Point(*coords)
    p_ = -p

    assert p.x == p_.x and p.y + p_.y == secp256k1.p


def test_neg_infinity():
    p = Point.inf()
    p_ = -p

    assert p == p_


@given(coords=st.sampled_from(POINTS))
def test_mul_other_not_int(coords):
    p = Point(*coords)

    with pytest.raises(ValueError):
        p * p

    with pytest.raises(ValueError):
        p * 1.2


@settings(deadline=None)
@given(data=st.sampled_from(MUL_POINTS))
def test_mul(data):
    coords_1, x, coords_2 = data
    p1 = Point(*coords_1)
    p2 = Point(*coords_2)

    assert p1 * x == x * p1 == p2
