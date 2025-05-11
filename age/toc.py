import os
import zlib
from dataclasses import dataclass
from io import BytesIO
from struct import unpack
from typing import Generator, IO


@dataclass
class TocEntry:
    offset: int
    enc_size: int
    size: int
    name: str

    def __post_init__(self):
        self.name = self.name.replace("\\", "/").strip("/")

    @property
    def has_encrypted_header(self):
        return self.enc_size > 0

    @property
    def real_file_size(self):
        if self.has_encrypted_header:
            return self.size - 12
        return self.size


def parse(zlib_toc: bytes) -> Generator[TocEntry, None, None]:
    data = BytesIO(zlib.decompress(zlib_toc))

    while chunk := data.read(14):
        data_offset, full_size, enc_size, name_len = unpack("<IIiH", chunk)
        name = data.read(name_len).decode("utf-8")
        yield TocEntry(offset=data_offset, enc_size=enc_size, size=full_size, name=name)


def parse_from_file(f: IO[bytes]) -> Generator[TocEntry, None, None]:
    f.seek(-20, os.SEEK_END)
    start_of_metadata, unk1, unk2, toc_start_addr, unk3 = unpack("<IIIII", f.read(20))
    f.seek(toc_start_addr, os.SEEK_SET)
    toc_compressed = f.read(start_of_metadata - toc_start_addr)
    return parse(toc_compressed)
