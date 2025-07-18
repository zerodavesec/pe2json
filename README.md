# PE to JSON Converter

This Python script extracts detailed information from a Portable Executable (PE) file (e.g., `.exe`, `.dll`) using the `pefile` library and saves it in a **properly formatted JSON file**.

## 🧠 Why This Script Exists

While the `pefile` library provides a convenient `dump_dict()` method to extract the structure of PE files, the resulting data often includes:

- **Non-serializable data** like `bytes`, `tuples`, and custom objects.
- **Byte-encoded dictionary keys**, which are not valid JSON keys.
- Data that causes `json.dump()` to fail or result in unreadable output.

This script solves these problems by **recursively converting all data** into formats compatible with JSON (e.g., converting bytes to hex strings, decoding byte keys, etc.).

---

## ✅ Features

- Converts complex PE structures into clean, readable JSON
- Handles `bytes`, `dicts`, `lists`, `tuples`, and other non-serializable types
- Preserves important PE metadata and layout
- Useful for reverse engineering, malware analysis, digital forensics, etc.
- Includes CLI interface for easy usage
- Programmatic API for integration into other projects
- Comprehensive error handling and logging

---

## 📦 Installation

```bash
pip install pefile
```

---

## 🚀 Usage

### Command Line Interface

```bash
# Convert a PE file to JSON
python pe_to_json.py path/to/file.exe output.json

# Convert a DLL to JSON
python pe_to_json.py library.dll library.json
```

#### Example:

```bash
python pe_to_json.py notepad.exe notepad.json
```

### Python API

```python
from pe_to_json import pe_to_json, convert_to_serializable
import pefile

# Convert PE file to JSON
pe_to_json("input.exe", "output.json")

# Or use the conversion function directly
pe = pefile.PE("input.exe")
pe_dict = pe.dump_dict()
serializable_dict = convert_to_serializable(pe_dict)

# Then save manually if needed
import json
with open("output.json", "w") as f:
    json.dump(serializable_dict, f, indent=4)
```

---

## 🛠 How It Works

### `convert_to_serializable(obj: Any)`

Recursively processes the `pefile` dump to:

- Convert `bytes` to hex strings
- Convert byte-string keys to UTF-8 strings with error handling
- Traverse and clean nested lists, dicts, and tuples
- Handle any non-serializable objects gracefully

### `pe_to_json(pe_file_path, json_file_path)`

- Loads the PE file with `pefile.PE`
- Converts the structure to a serializable format
- Writes the cleaned data to a JSON file with proper indentation
- Includes comprehensive error handling and informative logging

---

## 📁 Output

The resulting JSON file will contain:

- PE headers (DOS, NT, Optional headers)
- Section data (.text, .data, .rdata, etc.)
- Import/export tables
- Resource information
- Debug info
- Rich header information
- ...and more, all in a valid and readable format

---

## 📋 Requirements

- Python 3.8+
- [`pefile`](https://pypi.org/project/pefile/) library

---

## 🐞 Error Handling

The script handles:

- Missing files (`FileNotFoundError`)
- Invalid PE files (`pefile.PEFormatError`)
- Unexpected exceptions (with detailed logging and stack traces)

---

## 📄 License

MIT License — feel free to use, modify, and distribute.

---

## 🗺️ Roadmap

### Enhanced Output Options

- **Memory-based processing** - Keep parsed data in memory instead of always writing files
- **Direct string generation** - Output JSON as string variable for web applications
- **Chunked file handling** - Process massive PE files piece by piece to avoid memory issues
- **Output customization** - Let users control JSON spacing and organization

### Targeted Analysis

- **Focused extraction** - Parse only the PE sections you actually need
- **Data transformation** - Apply custom rules to modify output during conversion
- **Alternative formats** - Export to YAML or XML instead of JSON
- **Speed improvements** - Make large file processing much faster

### Workflow Integration

- **Directory scanning** - Analyze hundreds of PE files automatically
- **Database connectivity** - Send results directly to databases
- **Tool chaining** - Connect with other security analysis software
- **Remote analysis** - Accept PE files over HTTP for server-based processing

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

---

## 🔗 Related Tools

- [`pefile` on PyPI](https://pypi.org/project/pefile/)
- [PE format documentation (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE-bear](https://github.com/hasherezade/pe-bear-releases) - GUI PE analyzer
- [PEiD](https://www.aldeid.com/wiki/PEiD) - PE identifier tool
