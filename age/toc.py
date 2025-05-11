from dataclasses import dataclass
from struct import unpack
from typing import Generator
from zlib import decompress


@dataclass
class TocEntry:
    offset: int
    enc_size: int
    size: int
    name: str

    @property
    def has_encrypted_header(self):
        return self.enc_size > 0


def parse(zlib_toc: bytes) -> Generator[TocEntry, None, None]:
    data = decompress(zlib_toc)

    offset = 0
    while offset + 14 < len(data):
        data_offset, full_size, enc_size, name_len = unpack(
            "<IIiH", data[offset : offset + 14]
        )
        offset += 14

        name = data[offset : offset + name_len].decode("utf-8")
        offset += name_len

        yield TocEntry(offset=data_offset, enc_size=enc_size, size=full_size, name=name)
