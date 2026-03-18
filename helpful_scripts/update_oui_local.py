import argparse
import re
from pathlib import Path


OUI_PATTERN = re.compile(r"([0-9A-F]{6})\s+\(base 16\)\s+(.+)")
DEFAULT_OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent / "trackerjacker" / "oui.txt"
)


def get_oui(input_path, output_path=DEFAULT_OUTPUT_PATH):
    input_path = Path(input_path)
    output_path = Path(output_path)

    with input_path.open("r", encoding="utf-8", errors="replace") as src:
        lines = src.readlines()

    with output_path.open("w", encoding="utf-8") as out:
        for line in lines:
            match = OUI_PATTERN.match(line)
            if match:
                out.write(f"{match.group(1)}={match.group(2)}\n")


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path", help="Path to a local IEEE oui.txt file")
    parser.add_argument(
        "--output-path",
        default=str(DEFAULT_OUTPUT_PATH),
        help="Path to write the parsed OUI data",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    get_oui(args.input_path, args.output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
