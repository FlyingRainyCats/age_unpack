import hashlib
from struct import unpack
from typing import IO

from Crypto.Cipher import Blowfish

_AGE_KEY = hashlib.sha1(b"AGE Flash Player").digest()


class DCPBlowfishCFB:
    def __init__(self, key: bytes, iv: bytes | None = None):
        self.key = key
        self._ecb = Blowfish.new(key, Blowfish.MODE_ECB)
        self.iv = iv or self._ecb.encrypt(b"\0" * 8)

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes, n: int) -> bytes:
        return bytes((a[i] ^ b[i]) for i in range(n))

    @staticmethod
    def create_from_header(header: bytes):
        type_id, test_cipher, test_plain = unpack("<I4s4s", header[:12])
        if type_id != 5:
            raise RuntimeError(f"Unsupported cipher id: {type_id}")

        cipher = DCPBlowfishCFB(_AGE_KEY)
        cipher_ok = cipher.decrypt(test_cipher) == test_plain
        if not cipher_ok:
            raise RuntimeError(f"Cipher not matching: {test_cipher.hex()} != {test_plain.hex()}")
        return cipher

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
        n = len(plaintext)
        out = bytearray(n)
        offset = 0
        while n >= 8:
            plain_slice = plaintext[offset : offset + 8]
            temp = self._ecb.encrypt(self.iv)
            temp = self._xor_bytes(temp, plain_slice, 8)
            self.iv = out[offset : offset + 8] = temp
            offset += 8
            n -= 8

        if n % 8 != 0:
            self.iv = self._ecb.encrypt(self.iv)
            out[offset:] = self._xor_bytes(self.iv, plaintext[offset:], n)

        return bytes(out)

    def decrypt_stream(self, s_out: IO[bytes], s_in: IO[bytes], n: int):
        while n > 0:
            data = s_in.read(min(n, 0x2000))
            n -= len(data)
            s_out.write(self.decrypt(data))
