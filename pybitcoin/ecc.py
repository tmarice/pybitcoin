from collections import namedtuple
from copy import copy

Curve = namedtuple(
    'Curve', (
        'name',  # Curve name
        'a',  # y^2 = x^3 + a*x + b
        'b',  # y^2 = x^3 + a*x + b
        'p',  # Prime of the prime field
        'g_x',  # Generator point x coordinate
        'g_y',  # Generator point y coordinat

        # These two are not really relevant for calulations, but are left for completeness sake
        'n',  # Order of the prime field
        'h'  # Subgroup cofactor
    )
)

secp256k1 = Curve(
    name='secp256k1',
    a=0,
    b=7,
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    g_x=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    g_y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1,
)


class Point:
    __slots__ = ('x', 'y')
    curve = secp256k1

    def __init__(self, x, y):
        if x < 0 or y < 0:
            raise ValueError('Both coordinates have to be >= 0')
        if x >= self.curve.p or y >= self.curve.p:
            raise ValueError(f'Both coordinates have to < {self.curve.p}')
        if x and y and (pow(y, 2, self.curve.p) - pow(x, 3, self.curve.p) - 7) % self.curve.p != 0:
            raise ValueError('Point not on curve!')

        self.x = x
        self.y = y

    @classmethod
    def inf(cls):
        return Point(0, 0)

    @classmethod
    def gen(cls):
        '''Returns the generator point for current curve.

       This point can generate all other points in the curve's subgroup by multiplying it with integers [0, r], where
       r is order of the subgroup, i.e. the total number of points on the curve.
       For bitcoin curve -- secp256k1 -- cofactor is 1, meaning it has only 1 subgroup, which contains all the curve's
       points.
       '''
        return Point(cls.curve.g_x, cls.curve.g_y)

    def __str__(self):
        return f'({self.x}, {self.y})'

    def __repr__(self):
        return f'Point({self.x}, {self.y})'

    def __eq__(self, other):
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

    def __rmul__(self, other):
        return self * other

    def __mul__(self, other):
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
