from dataclasses import dataclass
from struct import unpack
from typing import cast, Generator
from zlib import decompress


@dataclass
class TocEntry:
    offset: int
    length: int
    unk1: int
    name: str


def parse(zlib_toc: bytes) -> Generator[TocEntry, None, None]:
    data = decompress(zlib_toc)

    offset = 0
    while offset + 14 < len(data):
        data_offset, unk, data_len, name_len = unpack(
            "<IIIH", data[offset : offset + 14]
        )
        offset += 14

        name = data[offset : offset + name_len].decode("utf-8")
        offset += name_len

        yield TocEntry(offset=data_offset, length=data_len, unk1=unk, name=name)
