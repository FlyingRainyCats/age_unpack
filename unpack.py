import argparse
import os

from age.toc import parse_from_file as parse_toc
from age.unpack import dump_file


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

    with open(args.input, "rb") as f_in:
        for file in parse_toc(f_in):
            if ".." in file.name:
                print(f"skip {file.name} (unsafe file path)")
                continue

            print(f"dumping {file.name} (size={file.size}, enc={file.enc_size}, offset=0x{file.offset:08x})...")
            out_path = os.path.join(args.output, file.name)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            with open(out_path, "wb") as f_out:
                dump_file(f_out, f_in, file)


if __name__ == "__main__":
    main()
