import argparse
import time
import sys

# Use pycryptodome's AES library
# See https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
from Cryptodome.Cipher import AES


KEY_ELEMENTS = ["KEY", "IV"]


def main(infile=None):
    lines = []

    # Checks, if interactive session or reading from a file
    if sys.stdin.isatty():
        if infile.name != "<stdin>":
            # Reads specification file
            with open(infile.name, "r") as f:
                lines = f.readlines()
        else:
            exit("Supply data via STDIN or file!")
    else:
        lines = sys.stdin.readlines()

    construct_key(lines)


def construct_key(lines):
    keymaterial = {}

    # Populates keymaterial
    for line in lines:
        # Strips of \n
        line = line.strip()

        # Tokenizes line
        parts = line.split("=", 1)
        name = parts[0]
        val = parts[-1]

        # Stores line in dict
        if name in KEY_ELEMENTS:
            keymaterial[name] = bytes(val, "utf-8")

    # Performs checks regarding well-formed key material
    if "KEY" not in keymaterial:
        exit("Key specification is incomplete.")
    elif (
        len(keymaterial["KEY"]) != 16
        and len(keymaterial["KEY"]) != 24
        and len(keymaterial["KEY"]) != 32
    ):
        exit("Unsupported key length: " + str(len(keymaterial["KEY"])))

    # Constructs AES key by given parameters
    # Assign it to a variable to keep it in memory
    if "IV" in keymaterial.keys():
        aes_key = AES.new(
            keymaterial["KEY"], AES.MODE_CBC, iv=keymaterial["IV"]
        )  # noqa: F841
    else:
        aes_key = AES.new(keymaterial["KEY"], AES.MODE_CBC)  # noqa: F841

    while True:
        time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Construct an AES key according to specified key material and sleep forever."  # noqa: E501
    )
    parser.add_argument(
        "keyspec", nargs="?", type=argparse.FileType("r"), default=sys.stdin
    )
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    construct_key(args.keyspec)
