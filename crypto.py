from io import BytesIO
from random import randint

import hashlib
import hmac


class PrvekTelesa:
    def __init__(self, cislo, char):
        self.cislo = cislo
        self.char = char

    def __eq__(self, other):
        if other is None:
            return False
        return self.cislo == other.cislo and self.char == other.char

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        cislo = (self.cislo + other.cislo) % self.char
        return self.__class__(cislo, self.char)

    def __sub__(self, other):
        cislo = (self.cislo - other.cislo) % self.char
        return self.__class__(cislo, self.char)

    def __mul__(self, other):
        cislo = (self.cislo * other.cislo) % self.char
        return self.__class__(cislo, self.char)

    def __pow__(self, exponent):
        n = exponent % (self.char - 1)
        cislo = pow(self.cislo, n, self.char)
        return self.__class__(cislo, self.char)

    def __truediv__(self, other):
        cislo = (self.cislo * pow(other.cislo, self.char - 2, self.char)) % self.char
        return self.__class__(cislo, self.char)

    def __rmul__(self, koef):
        cislo = (self.cislo * koef) % self.char
        return self.__class__(cislo=cislo, char=self.char)


class Bod:
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        if self.x is None:
            return other

        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, koef):
        coef = koef
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class S256Teleso(PrvekTelesa):
    def __init__(self, cislo, char=None):
        super().__init__(cislo=cislo, char=P)

    def __repr__(self):
        return '{:x}'.format(self.cislo).zfill(64)

    def sqrt(self):
        return self**((P + 1) // 4)

def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def encode_base58(s):
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    cislo = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while cislo > 0:
        cislo, mod = divmod(cislo, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(s):
    return encode_base58(s + hash256(s)[:4])

class S256Bod(Bod):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Teleso(A), S256Teleso(B)
        if type(x) == int:
            super().__init__(x=S256Teleso(x), y=S256Teleso(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __rmul__(self, koef):
        coef = koef % N
        return super().__rmul__(coef)

    def sec(self, compressed=True):
        if compressed:
            if self.y.cislo % 2 == 0:
                return b'\x02' + self.x.cislo.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.cislo.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.cislo.to_bytes(32, 'big') + self.y.cislo.to_bytes(32, 'big')

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)


G = S256Bod(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

def tvrzeny_priv(priv, chain, index=0):
    data = b'\x00' + priv + (pow(2, 31) + index).to_bytes(4, 'big') 
    newkey = hmac.new(chain, data, digestmod=hashlib.sha512).digest()
    child_priv = (int.from_bytes(newkey[:32], 'big') + int.from_bytes(priv, 'big')) % N
    return child_priv.to_bytes(32, 'big') + newkey[32:]

def netvrzeny_priv(priv, pub, chain, index=0):
    data = pub + index.to_bytes(4, 'big')
    newkey = hmac.new(chain, data, digestmod=hashlib.sha512).digest()
    child_priv = (int.from_bytes(newkey[:32], 'big') + int.from_bytes(priv, 'big')) % N
    return child_priv.to_bytes(32, 'big') + newkey[32:]