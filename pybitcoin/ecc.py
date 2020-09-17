from collections import namedtuple
from copy import copy
from enum import Enum
from math import log, floor


class Parity(Enum):
    ODD = 3
    EVEN = 2


Curve = namedtuple(
    'Curve',
    (
        'name',  # Curve name
        'a',  # y^2 = x^3 + a*x + b
        'b',  # y^2 = x^3 + a*x + b
        'p',  # Prime of the prime field
        'g_x',  # Generator point x coordinate
        'g_y',  # Generator point y coordinat
        # These two are not really relevant for calulations, but are left for completeness sake
        'n',  # Order of the prime field
        'h',  # Subgroup cofactor
    ),
)

secp256k1 = Curve(
    name='secp256k1',
    a=0,
    b=7,
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    g_x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    g_y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1,
)


class Point:
    __slots__ = ('x', 'y')
    curve = secp256k1

    def __init__(self, x:int, y: int):
        if x < 0 or y < 0:
            raise ValueError('Both coordinates have to be >= 0')
        if x >= self.curve.p or y >= self.curve.p:
            raise ValueError(f'Both coordinates have to < {self.curve.p}')
        if x and y and (pow(y, 2, self.curve.p) - pow(x, 3, self.curve.p) - 7) % self.curve.p != 0:
            raise ValueError('Point not on curve!')

        self.x = x
        self.y = y

    @classmethod
    def from_x(cls, x: int, parity: Parity):
        y1, y2 = tonelli_shanks(pow(x, 3, cls.curve.p) + 7, cls.curve.p)
        if parity == Parity.ODD:
            y = y1 if y1 & 1 else y2
        else:
            y = y2 if y1 & 1 else y1

        return cls(x, y)

    @classmethod
    def inf(cls):
        return Point(0, 0)

    @classmethod
    def gen(cls):
        """Returns the generator point for current curve.

        This point can generate all other points in the curve's subgroup by multiplying it with integers [0, r], where
        r is order of the subgroup, i.e. the total number of points on the curve.
        For bitcoin curve -- secp256k1 -- cofactor is 1, meaning it has only 1 subgroup, which contains all the curve's
        points.
        """
        return Point(cls.curve.g_x, cls.curve.g_y)

    def __str__(self):
        return f'({self.x}, {self.y})'

    def __repr__(self):
        return f'Point({self.x}, {self.y})'

    def __eq__(self, other) -> bool:
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if self.x == 0 and self.y == 0:
            return other
        if other.x == 0 and other.y == 0:
            return self

        if self.x == other.x and self.y == -other.y:
            return Point(0, 0)

        if self == other:
            s = 3 * pow(self.x, 2, self.curve.p) * pow(2 * self.y, -1, self.curve.p)
        else:
            s = (self.y - other.y) * pow(self.x - other.x, -1, self.curve.p)

        new_x = (pow(s, 2, self.curve.p) - self.x - other.x) % self.curve.p
        new_y = (s * (self.x - new_x) - self.y) % self.curve.p

        return Point(new_x, new_y)

    def __neg__(self):
        return Point(self.x, -self.y % self.curve.p)

    def __rmul__(self, other: int):
        return self * other

    def __mul__(self, other: int):
        if not isinstance(other, int):
            raise ValueError('Only scalar multiplication is defined!')

        if other == 1:
            return self
        if other < 0:
            return -(self * -other)

        n = copy(self)
        q = Point.inf()

        while other:
            if other % 2:
                q += n
            n += n
            other //= 2

        return q


def legendre(x, p):
    '''Determine if x is quadratic (non-)residue mod p.'''
    r = pow(x, p >> 1, p)
    if r == p - 1:
        return -1

    return r


def tonelli_shanks(n, p):
    # Check solution existance
    if legendre(n, p) != 1:
        raise ValueError(f'{n} is not a square root (mod {p})')

    # Factor p-1 to form q * 2^s, where q is odd
    q, s = p - 1, 0
    while q & 1 == 0:
        s += 1
        q >>= 1

    # Find z which is quadratic non-residue 
    z = 1
    while legendre(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) >> 1, p)

    while t != 1:
        # Find the least i s.t. t^(2^i) = 1 mod p
        t2i = t
        for i in range(1, m):
            t2i = t2i * t2i % p
            if t2i == 1:
                break

        b = pow(c, 2 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = t * c % p
        r = r * b % p

    return r, p - r
