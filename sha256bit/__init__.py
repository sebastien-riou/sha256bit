import copy
import struct
import binascii


class sha256bit(object):
    F32 = 0xFFFFFFFF

    _k = [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ]

    _h_init = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    @staticmethod
    def _rotr(x, y):
        return ((x >> y) | (x << (32 - y))) & sha256bit.F32

    @staticmethod
    def _maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def _ch(x, y, z):
        return (x & y) ^ ((~x) & z)

    _output_size = 8
    blocksize = 1
    block_size = 64
    digest_size = 32

    def __init__(self, m=None, *, bitlen=None):
        """SHA-256 implementation supporting bit granularity for message input length.
        API is the same as hashlib.
        """
        self._counter = 0
        self._cache = bytearray()
        self._h = copy.deepcopy(sha256bit._h_init)
        self._has_bitlen = False
        self._digest = None
        self.update(m, bitlen=bitlen)

    def export_state(self):
        if self._digest is None:
            h = self._h
            c = self._cache
        else:
            h = self._digest
            c = None
        return {"h": h, "cnt": self._counter, "cache": c}

    @staticmethod
    def import_state(state):
        o = sha256bit()
        o._counter = state["cnt"]
        if 0 != (o._counter % 8):
            o._has_bitlen = True
        if state["cache"] is None:
            o._digest = state["h"]
            o._h = None
            o._cache = None
        else:
            o._h = state["h"]
            o._cache = bytearray(state["cache"])
        return o

    def _compress(self, c):
        w = [0] * 64
        w[0:16] = struct.unpack("!16L", c)
        for i in range(16, 64):
            s0 = (
                sha256bit._rotr(w[i - 15], 7)
                ^ sha256bit._rotr(w[i - 15], 18)
                ^ (w[i - 15] >> 3)
            )
            s1 = (
                sha256bit._rotr(w[i - 2], 17)
                ^ sha256bit._rotr(w[i - 2], 19)
                ^ (w[i - 2] >> 10)
            )
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & sha256bit.F32

        a, b, c, d, e, f, g, h = self._h

        for i in range(64):
            s0 = sha256bit._rotr(a, 2) ^ sha256bit._rotr(a, 13) ^ sha256bit._rotr(a, 22)
            t2 = s0 + sha256bit._maj(a, b, c)
            s1 = sha256bit._rotr(e, 6) ^ sha256bit._rotr(e, 11) ^ sha256bit._rotr(e, 25)
            t1 = h + s1 + sha256bit._ch(e, f, g) + sha256bit._k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & sha256bit.F32
            d = c
            c = b
            b = a
            a = (t1 + t2) & sha256bit.F32

        for i, (x, y) in enumerate(zip(self._h, [a, b, c, d, e, f, g, h])):
            self._h[i] = (x + y) & sha256bit.F32

    def update(self, m, *, bitlen=None):
        """Update the hash object with the bytes in data. Repeated calls
        are equivalent to a single call with the concatenation of all
        the arguments.
        """
        if not m:
            return
        assert not self._has_bitlen, "we support bitlen only for last call"
        if bitlen is not None:
            if 0 != (bitlen % 8):
                self._has_bitlen = True
            else:
                assert bitlen == len(m) * 8, "bitLen=%d, len(m)*8=%d" % (
                    bitlen,
                    len(m) * 8,
                )
            self._counter += bitlen
        else:
            self._counter += len(m) * 8

        self._cache += m

        while len(self._cache) > 64:
            self._compress(self._cache[:64])
            self._cache = self._cache[64:]

        if len(self._cache) == 64:
            if 0 != (self._counter % 8):
                assert self._has_bitlen
                # at least one bit is issing to form a full block, nothing to do
            else:
                self._compress(self._cache[:64])
                self._cache = self._cache[64:]

    def _pad(self):
        lastBlockBitLen = self._counter % 512
        lastBlockFullBytesCnt = lastBlockBitLen // 8
        if lastBlockBitLen < 448:
            padlen = 55 - lastBlockFullBytesCnt
        else:
            padlen = 119 - lastBlockFullBytesCnt
        if False:
            print(lastBlockBitLen, lastBlockFullBytesCnt, padlen, len(self._cache))

        shift = self._counter % 8
        if shift > 0 and (len(self._cache) > 0):
            mask = 0xFF << (8 - shift)
            self._cache[-1] = (self._cache[-1] & mask) | (0x80 >> shift)
        else:
            self._cache += b"\x80"
        self._cache += (b"\x00" * padlen) + self._counter.to_bytes(8, byteorder="big")
        if False:
            from pysatl import Utils

            print("counter=%d (0x%x)" % (self._counter, self._counter))
            print(Utils.hexstr(self._cache))
        assert len(self._cache) in [64, 128], "len(self._cache)=%d" % len(self._cache)

    def digest(self):
        """Return the digest of the bytes passed to the update() method
        so far as a bytes object.
        """
        if self._digest is not None:
            return self._digest
        self._pad()
        blocks = [self._cache[i : i + 64] for i in range(0, len(self._cache), 64)]
        for b in blocks:
            self._compress(b)
        data = [struct.pack("!L", i) for i in self._h[: self._output_size]]
        self._digest = b"".join(data)
        self._cache = None
        self._h = None
        return self._digest

    def hexdigest(self):
        """Like digest() except the digest is returned as a string
        of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.digest()).decode("ascii")
