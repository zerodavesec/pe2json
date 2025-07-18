import unittest
from unittest.mock import MagicMock, mock_open, patch

import pefile

from pe2json.pe2json import convert_to_serializable, pe_to_json


class TestConvertToSerializable(unittest.TestCase):
    def test_bytes_to_hex(self):
        self.assertEqual(convert_to_serializable(b"\x01\xff"), "01ff")

    def test_list_with_bytes(self):
        result = convert_to_serializable([b"\x01", "text", 123])
        self.assertEqual(result, ["01", "text", 123])

    def test_dict_with_bytes_keys_values(self):
        result = convert_to_serializable({b"key": b"\xff", "normal": "value"})
        self.assertEqual(result, {"key": "ff", "normal": "value"})

    def test_nested_structure(self):
        data = {"level1": [b"\x01", {"level2": b"\xff"}]}
        result = convert_to_serializable(data)
        self.assertEqual(result, {"level1": ["01", {"level2": "ff"}]})


class TestPeToJson(unittest.TestCase):
    @patch("pe2json.pe2json.pefile.PE")
    @patch("builtins.open", new_callable=mock_open)
    def test_successful_conversion(self, mock_file, mock_pe_class):
        mock_pe = MagicMock()
        mock_pe.dump_dict.return_value = {"test": b"\x01\x02"}
        mock_pe_class.return_value = mock_pe

        pe_to_json("test.exe", "output.json")

        mock_pe_class.assert_called_once_with("test.exe")
        mock_file.assert_called_once_with("output.json", "w", encoding="utf-8")

    @patch("pe2json.pe2json.pefile.PE")
    @patch("pe2json.pe2json.logger")
    def test_file_not_found(self, mock_logger, mock_pe_class):
        mock_pe_class.side_effect = FileNotFoundError()

        pe_to_json("missing.exe", "output.json")

        mock_logger.error.assert_called_once_with("File not found: missing.exe")

    @patch("pe2json.pe2json.pefile.PE")
    @patch("pe2json.pe2json.logger")
    def test_pe_format_error(self, mock_logger, mock_pe_class):
        mock_pe_class.side_effect = pefile.PEFormatError("Invalid PE")

        pe_to_json("bad.exe", "output.json")

        mock_logger.error.assert_called_once_with("PEFormatError: 'Invalid PE'")


if __name__ == "__main__":
    unittest.main()
