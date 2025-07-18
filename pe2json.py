import json
import logging
from typing import Any

import pefile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def convert_to_serializable(obj: Any) -> str | list[Any] | dict[str, Any]:
    """
    Recursively convert non-serializable objects (e.g., bytes) into serializable formats.
    """
    if isinstance(obj, bytes):
        return obj.hex()
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {
            key.decode("utf-8", errors="replace")
            if isinstance(key, bytes)
            else key: convert_to_serializable(value)
            for key, value in obj.items()
        }
    return obj


def pe_to_json(pe_file_path: str, json_file_path: str) -> None:
    """
    Parses a PE (Portable Executable) file and saves its structure to a JSON file.

    Args:
        pe_file_path (str): Path to the PE file (e.g., .exe, .dll).
        json_file_path (str): Path to save the JSON output.
    """
    try:
        logger.info(f"Loading PE file from: {pe_file_path}")
        pe = pefile.PE(pe_file_path)

        logger.info("Dumping PE data...")
        pe_dict = pe.dump_dict()
        serializable_dict = convert_to_serializable(pe_dict)

        logger.info(f"Writing PE information to JSON: {json_file_path}")
        with open(json_file_path, "w", encoding="utf-8") as json_file:
            json.dump(serializable_dict, json_file, indent=4)

        logger.info("PE information successfully written to JSON.")

    except FileNotFoundError:
        logger.error(f"File not found: {pe_file_path}")
    except pefile.PEFormatError as e:
        logger.error(f"PEFormatError: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Convert a PE file's structure into JSON format."
    )
    parser.add_argument("pe_file", help="Path to the input PE file (.exe, .dll, etc.)")
    parser.add_argument("output_json", help="Path to the output JSON file")
    args = parser.parse_args()

    pe_to_json(args.pe_file, args.output_json)


if __name__ == "__main__":
    main()
