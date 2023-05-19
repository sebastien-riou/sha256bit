import copy
import struct
import binascii

class sha256bit(object):

    F32 = 0xFFFFFFFF

    _k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    _h_init = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

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

    def __init__(self, m=None):
        """ SHA-256 implementation supporting bit granularity for message input length.
            API is the same as hashlib.
        """
        self._counter = 0
        self._cache = bytearray()
        self._h = copy.deepcopy(sha256bit._h_init)
        self.hasBitLen = False 
        self.finalizing = False
        self._digest = None
        self.update(m)

    def internal_state(self):
        return {"h":self._h, "cnt":self._counter, "cache":self._cache}

    def _compress(self, c):
        w = [0] * 64
        w[0:16] = struct.unpack('!16L', c)
        for i in range(16, 64):
            s0 = sha256bit._rotr(w[i-15], 7) ^ sha256bit._rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = sha256bit._rotr(w[i-2], 17) ^ sha256bit._rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & sha256bit.F32

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

    def update(self, m, *, bitLen=None):
        """ Update the hash object with the bytes in data. Repeated calls
            are equivalent to a single call with the concatenation of all
            the arguments.
        """
        if not m:
            return

        if self.hasBitLen: 
            assert self.finalizing, "we support bitLen only for last block"
        
        if bitLen is not None:
            if 0 != (bitLen%8):
                self.hasBitLen = True
            else:
                assert bitLen == len(m)*8, "bitLen=%d, len(m)*8=%d"%(bitLen,len(m)*8)
            self._counter += bitLen
        else:
            self._counter += len(m)*8
        
        self._cache += m
        
        while len(self._cache) > 64:
            self._compress(self._cache[:64])
            self._cache = self._cache[64:]

        if len(self._cache) == 64:
            if 0 != (self._counter % 8):
                assert self.hasBitLen
                # at least one bit is issing to form a full block, nothing to do
            else:
                self._compress(self._cache[:64])
                self._cache = self._cache[64:]

    def _pad(self):
        lastBlockBitLen = self._counter % 512
        lastBlockFullBytesCnt = lastBlockBitLen//8
        if lastBlockBitLen < 448:
            padlen = 55 - lastBlockFullBytesCnt
        else:
            padlen = 119 - lastBlockFullBytesCnt
        if False:
            print(lastBlockBitLen,lastBlockFullBytesCnt,padlen, len(self._cache))
        
        shift = self._counter % 8
        if shift>0 and (len(self._cache)>0):
            mask = 0xFF << (8-shift)
            self._cache[-1] = (self._cache[-1] & mask) | (0x80 >> shift)
        else:
            self._cache += b'\x80'
        self._cache += (b'\x00' * padlen) + self._counter.to_bytes(8,byteorder='big')
        if False:
            from pysatl import Utils
            print("counter=%d (0x%x)"%(self._counter,self._counter))
            print(Utils.hexstr(self._cache))
        assert len(self._cache) in [64,128], "len(self._cache)=%d"%len(self._cache)
    
    def digest(self):
        """ Return the digest of the bytes passed to the update() method
            so far as a bytes object.
        """
        if self._digest is not None:
            return self._digest
        self._pad()
        blocks = [self._cache[i:i+64] for i in range(0, len(self._cache), 64)]
        for b in blocks:
            self._compress(b)
        data = [struct.pack('!L', i) for i in self._h[:self._output_size]]
        self._digest = b''.join(data)
        return self._digest

    def hexdigest(self):
        """ Like digest() except the digest is returned as a string
            of double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.digest()).decode('ascii')
    
