from struct import Struct
from Crypto.Util.number import getPrime

class PKE:

    def __init__(self, header_size = 10):
        self.HEADER_SIZE = header_size

    def getRandomKey(self, b: int)-> None:
        p = getPrime(b)
        q = getPrime(b)
        while p == q: q = getPrime(b)
        self.e = 0x10001
        self.n = p*q
        phi = self.n-p-q+1
        self.d = pow(self.e, -1, phi)

    def sharePubKey(self)-> bytes:
        e = hex(self.e)[2:]
        if len(e) & 1: e = '0' + e
        e = bytes.fromhex(e)
        h1 = f'{hex(len(e))[2:]:>0{self.HEADER_SIZE}}'.encode()
        n = hex(self.n)[2:]
        if len(n) & 1: n = '0' + n
        n = bytes.fromhex(n)
        h2 = f'{hex(len(n))[2:]:>0{self.HEADER_SIZE}}'.encode()
        pk = h1 + e + h2 + n
        return pk

    def recvPubKey(self, pk: bytes)-> None:
        h1 = int(pk[:self.HEADER_SIZE].decode(), 16)
        pk = pk[self.HEADER_SIZE:]
        self.e = int(pk[:h1].hex(), 16)
        pk = pk[h1:]
        h2 = int(pk[:self.HEADER_SIZE].decode(), 16)
        pk = pk[self.HEADER_SIZE:]
        self.n = int(pk[:h2].hex(), 16)
        self.d = 0

    def encrypt(self, data: bytes)-> bytes:
        m = int(data.hex(), 16)
        c = pow(m, self.e, self.n)
        c = hex(c)[2:]
        if len(c) & 1: c = '0' + c
        c = bytes.fromhex(c)
        return c
    
    def decrypt(self, data: bytes)-> bytes:
        c = int(data.hex(), 16)
        m = pow(c, self.d, self.n)
        m = hex(m)[2:]
        if len(m) & 1: m = '0' + m
        m = bytes.fromhex(m)
        return m

class MyHash(object):

    digest_size = 8 # bytes
    block_size = 8 # bytes

    _zeroes = b'\x00' * 8
    _oneQ = Struct('<Q')
    _twoQ = Struct('<QQ')

    s = b''
    b = 0

    def __init__(self, secret, s=b''):
        k0, k1 = self._twoQ.unpack(secret)
        self.v = (
            0x736f6d6570736575 ^ k0,
            0x646f72616e646f6d ^ k1,
            0x6c7967656e657261 ^ k0,
            0x7465646279746573 ^ k1
        )
        self.update(s)

    def double_round(self, v, m):
        a, b, c, d = v
        d ^= m

        e = (a + b) & 0xffffffffffffffff
        i = (((b & 0x7ffffffffffff) << 13) | (b >> 51)) ^ e
        f = c + d
        j = (((d << 16) | (d >> 48)) ^ f ) & 0xffffffffffffffff
        h = (f + i) & 0xffffffffffffffff

        k = ((e << 32) | (e >> 32)) + j
        l = (((i & 0x7fffffffffff) << 17) | (i >> 47)) ^ h
        o = (((j << 21) | (j >> 43)) ^ k) & 0xffffffffffffffff

        p = (k + l) & 0xffffffffffffffff
        q = (((l & 0x7ffffffffffff) << 13) | (l >> 51)) ^ p
        r = ((h << 32) | (h >> 32)) + o
        s = (((o << 16) | (o >> 48)) ^ r) & 0xffffffffffffffff
        t = (r + q) & 0xffffffffffffffff
        u = (((p << 32) | (p >> 32)) + s) & 0xffffffffffffffff

        return (
            u ^ m,
            (((q & 0x7fffffffffff) << 17) | (q >> 47)) ^ t,
            ((t & 0xffffffff) << 32) | (t >> 32),
            (((s & 0x7ffffffffff) << 21) | (s >> 43)) ^ u
        )

    def update(self, s):
        s = self.s + s
        lim = (len(s)>>3)<<3
        v = self.v
        off = 0

        for off in range(0, lim, 8):
            m, = self._oneQ.unpack_from(s, off)
            v = self.double_round(v, m)

        self.v = v
        self.b += lim
        self.s = s[lim:]
        return self

    def hash(self):
        l = len(self.s)
        assert l < 8

        b = ((self.b + l) & 0xff) << 56
        b |= self._oneQ.unpack_from(self.s + self._zeroes)[0]
        v = self.v
        v = self.double_round(v, b)
        v = list(v)
        v[2] ^= 0xff
        v = self.double_round(self.double_round(v, 0), 0)

        return v[0]^v[1]^v[2]^v[3]

    def digest(self):
        return self._oneQ.pack(self.hash())


class HMAC:

    def __init__(self, secret: bytes):
        self.secret = secret

        ipad = 0x36
        opad = 0x5c
        for _ in range(MyHash.block_size-1):
            ipad <<= 8
            ipad |= 0x36
            opad <<= 8
            opad |= 0x5c

        _oneQ = Struct('<Q')
        k, = _oneQ.unpack(secret[:8])

        self.v = (
            _oneQ.pack(k ^ ipad),
            _oneQ.pack(k ^ opad)
        )

    def getMAC(self, data: bytes):
        md = MyHash(self.secret).update(self.v[0] + data).digest()
        md = MyHash(self.secret).update(self.v[1] + md).digest()
        return md

    def verify(self, data: bytes, mac: bytes):
        _mac = self.getMAC(data)
        return mac == _mac
