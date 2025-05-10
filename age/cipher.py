import hashlib
from io import BytesIO

from Crypto.Cipher import Blowfish

key_id = b"AGE Flash Player"


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


class DCPBlowfishCFB:
    def __init__(self, key: bytes, iv: bytes | None = None):
        self.key = key
        self._ecb = Blowfish.new(key, Blowfish.MODE_ECB)
        self.iv = iv or self._ecb.encrypt(b"\0" * 8)

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes, n: int) -> bytes:
        return bytes((a[i] ^ b[i]) for i in range(n))

    @staticmethod
    def from_aeg():
        return DCPBlowfishCFB(sha1(key_id))

    def decrypt(self, ciphertext: bytes) -> bytes:
        n = len(ciphertext)
        out = bytearray(n)
        offset = 0
        while n >= 8:
            block = ciphertext[offset : offset + 8]
            temp = self._ecb.encrypt(self.iv)
            out[offset : offset + 8] = self._xor_bytes(temp, block, 8)
            self.iv = block
            offset += 8
            n -= 8

        if n % 8 != 0:
            self.iv = self._ecb.encrypt(self.iv)
            out[offset:] = self._xor_bytes(self.iv, ciphertext[offset:], n)

        return bytes(out)

    def encrypt(self, plaintext: bytes) -> bytes:
        """未测试"""
        n = len(plaintext)
        out = bytearray(n)
        offset = 0
        while n >= 8:
            block = plaintext[offset : offset + 8]
            temp = self._ecb.encrypt(self.iv)
            temp = self._xor_bytes(temp, block, 8)
            out[offset : offset + 8] = temp
            self.iv = temp
            offset += 8
            n -= 8

        if n % 8 != 0:
            self.iv = self._ecb.encrypt(self.iv)
            out[offset:] = self._xor_bytes(self.iv, plaintext[offset:], n)

        return bytes(out)

    def decrypt_stream(self, s_out: BytesIO, s_in: BytesIO, n: int):
        while n > 0:
            data = s_in.read(max(n, 0x2000))
            n -= len(data)
            s_out.write(self.decrypt(data))
