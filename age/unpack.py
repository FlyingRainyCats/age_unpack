import os
from typing import IO

from age.cipher import DCPBlowfishCFB
from age.toc import TocEntry


def dump_file(f_out: IO[bytes], f_in: IO[bytes], file: TocEntry):
    f_in.seek(file.offset, os.SEEK_SET)
    if file.has_encrypted_header:
        cipher = DCPBlowfishCFB.create_from_header(f_in.read(12))
        cipher.decrypt_stream(f_out, f_in, file.enc_size)
        to_copy_len = file.size - file.enc_size - 12
    else:
        to_copy_len = file.size

    while to_copy_len > 0:
        chunk_len = min(to_copy_len, 0x2000)
        f_out.write(f_in.read(chunk_len))
        to_copy_len -= chunk_len
