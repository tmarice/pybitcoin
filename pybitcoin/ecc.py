from collections import namedtuple
from copy import copy

# TODO: integrate into Point class
Curve = namedtuple('Curve', ('name', 'a', 'b', 'p', 'g_x', 'g_y', 'n', 'h'))


class Point:
    __slots__ = ('x', 'y')

    def __init__(self, x, y):
        if x < 0 or y < 0:
            raise ValueError('Both coordinates have to be >= 0')
        if x >= P or y >= P:
            raise ValueError(f'Both coordinates have to < {P}')
        if x and y and (pow(y, 2, P) - pow(x, 3, P) - 7) % P != 0:
            raise ValueError('Point not on curve!')

        self.x = x
        self.y = y

    @classmethod
    def inf(cls):
        return Point(0, 0)

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
            s = 3 * pow(self.x, 2) * pow(2 * self.y, -1, P)
        else:
            s = (self.y - other.y) * pow(self.x - other.x, -1, P)

        new_x = (pow(s, 2) - self.x - other.x) % P
        new_y = (s * (self.x - new_x) - self.y) % P

        return Point(new_x, new_y)

    def __neg__(self):
        return Point(self.x, -self.y % P)

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


# Prime of the prime field Fp
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Generator point - this point can generate all other points in the curve's
# subgroup by multiplying it with integers [0, r], where r is order of the
# subgroup, i.e. the total number of points on the curve
# For bitcoin curve -- secp256k1 -- cofactor is 1, meaning it has only 1
# subgroup, which contains all the curve's points
G = Point(
    x=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)
