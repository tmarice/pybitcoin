import pytest
from pybitcoin.ecc import secp256k1, Point
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


# TODO: refactor these 2 tests somehow: do not duplicate code
@given(
    x=st.integers(),
    y=st.integers(min_value=secp256k1.p),
)
def test_point_rejects_larger_than_curve_p(x, y):
    '''Point raises ValueError if y coordinate is larger than curve's prime.'''
    with pytest.raises(ValueError):
        Point(x, y)


@given(
    x=st.integers(min_value=secp256k1.p),
    y=st.integers(),
)
def test_point_rejects_larger_than_curve_p(x, y):
    '''Point raises ValueError if x coordinate is larger than curve's prime.'''
    with pytest.raises(ValueError):
        Point(x, y)


@given(
    x=st.integers(min_value=1, max_value=secp256k1.p - 1),
    y=st.integers(min_value=1, max_value=secp256k1.p - 1),
)
def test_point_rejects_coordinates_not_on_curve(x, y):
    '''Point raises ValueError if coordinates are not on SECP256K1 curve.'''
    assume((pow(y, 2, secp256k1.p) - pow(x, 3, secp256k1.p) - 7 % secp256k1.p) != 0)
    with pytest.raises(ValueError):
        Point(x, y)


def test_point_accepts_coordinates_on_curve():
    '''Point constructor doesn't raise for valid coordinates on SECP256K1 curve.'''
    pass


def test_point_from_x_odd():
    pass
