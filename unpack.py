import argparse
import os
from struct import unpack
import age
from age.cipher import DCPBlowfishCFB


def main():
    parser = argparse.ArgumentParser(description="AEG ebook unpacker")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="out/",
        help="Output directory (default: out/)",
    )
    parser.add_argument(
        "input",
        type=str,
        help="Input file",
    )
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        f.seek(-20, os.SEEK_END)
        start_of_metadata, unk1, unk2, toc_start_addr, unk3 = unpack(
            "<IIIII", f.read(20)
        )
        f.seek(toc_start_addr, os.SEEK_SET)

        for file in age.toc.parse(f.read(start_of_metadata - toc_start_addr)):
            out_path = os.path.join(args.output, file.name.replace("\\", "/"))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            f.seek(file.offset, os.SEEK_SET)
            type_id, test_cipher, test_plain = unpack("<I4s4s", f.read(12))
            if type_id != 5:
                print(f"warn: unknown cipher id: {type_id}")
                continue
            cipher = DCPBlowfishCFB.from_aeg()
            cipher_ok = cipher.decrypt(test_cipher) == test_plain
            if not cipher_ok:
                print("warn: cipher value mismatch")
                continue

            print(f"dump {file.name} (len={file.length})...")
            with open(out_path, "wb") as out_f:
                cipher.decrypt_stream(out_f, f, file.length)


if __name__ == "__main__":
    main()
