# EXE Resource Extractor

A Python-based static PE resource extractor designed to inspect Windows executables and recover embedded resources, including batch scripts stored inside compiled `.exe` files.

The tool examines the executable's Portable Executable (PE) resource directory, extracts available resources, attempts zlib decompression, and checks selected RCDATA payloads for RC4-encrypted readable text.

It is designed for file inspection without launching the target executable.

---

## Overview

Windows applications can contain resources such as icons, manifests, version information, configuration data, and embedded payloads.

Some BAT-to-EXE tools package `.bat` scripts inside Windows executables. Depending on the packaging method, the embedded script may be stored in compressed or encrypted form.

This project provides a way to inspect that resource data and recover supported payloads for analysis.

### Features

- **PE Resource Extraction** — Parses Windows PE resource directories without external dependencies.
- **Batch Payload Recovery** — Attempts to recover RC4-encrypted batch scripts from embedded RCDATA resources.
- **Zlib Decompression** — Automatically detects and decompresses compatible zlib data.
- **Resource Dumping** — Extracts icons, manifests, RCDATA, version information, and other available resources.
- **SHA-256 Hashing** — Generates hashes for the original executable and recovered payloads.
- **Custom Output Directory** — Choose where extracted resources are saved.
- **Custom RC4 Key** — Supports specifying a key through command-line arguments.
- **Static Analysis** — Does not intentionally execute the target executable.
- **Safer Payload Handling** — Recovered batch scripts are saved as `.txt` files rather than executable `.bat` files.

### What it does not do

- Execute the target executable.
- Execute recovered batch scripts.
- Reconstruct the complete original source code of a compiled application.
- Decompile native C or C++ machine code into its original source.
- Automatically bypass every executable packer or protection.
- Guarantee recovery of every embedded script.

---

## How It Works

The extractor follows a resource-analysis workflow.

### 1. PE File Validation

The input file is checked for the Windows `MZ` header and PE signature.

The script then reads information from the executable's headers, including:

- Machine architecture
- Number of sections
- Optional header format
- Image base
- Resource directory information

Both PE32 and PE32+ optional header formats are recognized.

### 2. Section Mapping

The executable's section table is parsed.

The `rva2off()` function translates Relative Virtual Addresses (RVAs) into file offsets so that resource structures can be accessed from the raw executable data.

### 3. Resource Directory Traversal

The resource directory is recursively traversed.

Resources are collected with their associated resource paths and code-page metadata.

The extractor recognizes common Windows resource identifiers:

| Resource ID | Resource Type |
|---|---|
| 1 | CURSOR |
| 2 | BITMAP |
| 3 | ICON |
| 4 | MENU |
| 5 | DIALOG |
| 6 | STRING |
| 8 | FONT |
| 9 | ACCELERATOR |
| 10 | RCDATA |
| 11 | MESSAGETABLE |
| 14 | GROUP_ICON |
| 16 | VERSION |
| 24 | MANIFEST |

Named resources are also supported by the resource traversal logic.

### 4. Resource Dumping

Every collected resource is written to the selected output directory.

Files are named according to their resource type, resource name, and language identifier.

Example:

```text
RCDATA__103__1033.bin
ICON__1__1033.bin
VERSION__1__1033.bin
```

The extracted files retain their original binary content.

### 5. Zlib Decompression

The script checks resource data beginning with the `0x78` byte, which is commonly associated with zlib streams.

When decompression succeeds, the resulting data is saved separately.

```text
RCDATA__103__1033.inflated.bin
```

This is useful when a resource contains compressed configuration data.

### 6. RC4 Payload Recovery

Selected RCDATA resources are tested using the configured RC4 key.

The extractor includes an RC4 implementation written in Python.

Recovered data is checked for readable text. When a payload meets the text-detection criteria, it is saved as:

```text
DECRYPTED__103.txt
```

The `.txt` extension is intentional. The recovered content is not automatically executed.

### 7. SHA-256 Reporting

The tool calculates SHA-256 hashes for:

- The original executable.
- Successfully recovered text payloads.

These hashes can help identify files and compare extraction results.

---

## Requirements

| Requirement | Details |
|---|---|
| Operating System | Windows recommended |
| Python | Python 3.x |
| Dependencies | Python standard library |
| Internet Connection | Not required |
| Administrator Privileges | Not normally required |

The script uses standard Python modules:

```python
argparse
hashlib
os
struct
sys
zlib
```

No external PE parsing library such as `pefile` is required.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
```

### 2. Navigate to the project directory

```bash
cd YOUR-REPOSITORY
```

### 3. Run the script

```bash
python Decompile_Exe_Compiled_Bat.py
```

You can also use the Windows Python launcher:

```bash
py Decompile_Exe_Compiled_Bat.py
```

---

## Usage

### Specify an executable

Place your target executable in the project directory or provide its full path.

```bash
python Decompile_Exe_Compiled_Bat.py "Example.exe"
```

You can also provide an absolute path:

```bash
python Decompile_Exe_Compiled_Bat.py "C:\Analysis\Example.exe"
```

### Specify a custom output directory

```bash
python Decompile_Exe_Compiled_Bat.py "Example.exe" -o extracted_resources
```

### Specify a custom RC4 key

```bash
python Decompile_Exe_Compiled_Bat.py "Example.exe" --key YOUR_KEY
```

### Display available arguments

```bash
python Decompile_Exe_Compiled_Bat.py --help
```

### Command-line arguments

| Argument | Description |
|---|---|
| `exe` | Input executable path |
| `-o`, `--outdir` | Custom extraction directory |
| `-k`, `--key` | RC4 key used for payload recovery |
| `-h`, `--help` | Display help information |

---

## Example Output

A successful extraction may produce console output similar to:

```text
file      : Example.exe
size      : 000000 bytes
sha256    : [SHA-256 HASH]
machine   : 0x8664  image base: 0x140000000

TYPE       NAME                                       LANG     SIZE
----------------------------------------------------------------------
ICON       1                                          1033     0000
VERSION    1                                          1033     0000
RCDATA     103                                        1033     0000
    zlib   -> RCDATA__103__1033.inflated.bin
    RC4    -> DECRYPTED__103.txt

done. resources written to: [OUTPUT DIRECTORY]
```

The actual resource names, sizes, and extraction results depend on the input executable.

---

## Project Structure

```text
EXE-Resource-Extractor/
│
├── Decompile_Exe_Compiled_Bat.py
├── README.md
├── LICENSE
│
└── extracted_resources/
    ├── RCDATA__103__1033.bin
    ├── RCDATA__103__1033.inflated.bin
    ├── ICON__1__1033.bin
    ├── VERSION__1__1033.bin
    └── DECRYPTED__103.txt
```

The `extracted_resources` directory is generated during execution. It is not required to run the script.

---

## BAT to EXE Converters

This project is useful for examining executables that contain batch-script payloads.

The following are third-party resources related to BAT-to-EXE conversion.

| Project | Website |
|---|---|
| BAT to EXE Converter | https://www.battoexe.com/ |
| Advanced BAT to EXE Converter | https://www.battoexeconverter.com/ |
| ExeFoundry | https://github.com/the-sudipta/ExeFoundry |
| ExeFoundry Releases | https://github.com/the-sudipta/ExeFoundry/releases |

These tools are not dependencies of this project and are maintained independently.

---

## Security & Protection Against Unauthorized Inspection

If you distribute a batch-based utility, you should understand the limitations of compiled batch files.

A `.bat` file is plain text and can be opened directly in a text editor.

A compiled `.exe` may conceal the script's contents from casual inspection, depending on how it was packaged.

However:

- Compilation does not guarantee that the script cannot be recovered.
- Encryption does not guarantee protection against reverse engineering.
- Hardcoded passwords, API keys, tokens, and private credentials should never be placed inside a distributed executable.
- A compiled batch utility can still contain unsafe commands.
- Antivirus software may flag some packed or encrypted executables.

**Do not rely on BAT-to-EXE conversion alone to prevent hacking.**

For stronger protection, avoid embedding secrets in client-side code, use proper authentication on a server, and keep sensitive operations under server-side control.

---

## Safety Notice

This project performs static extraction and does not intentionally execute the input executable.

Recovered `.txt` files should still be treated as untrusted data.

Before analyzing an unknown executable:

- Keep Windows Defender or another reputable security product enabled.
- Do not run unknown executables as administrator.
- Inspect recovered scripts before attempting to use them.
- Consider using an isolated virtual machine for suspicious files.
- Do not analyze executables without appropriate authorization.

Static extraction does not establish that the input executable is safe. It may contain behavior outside the resource directory.

---

## Limitations

The current implementation is specifically designed around PE resource extraction and the expected payload format.

Potential limitations include:

- Unsupported or malformed PE structures may cause extraction errors.
- Resources with unusual layouts may not be recovered correctly.
- RVA-to-file-offset mapping depends on valid section information.
- RC4 recovery depends on the correct key.
- Readable-text detection may miss valid payloads or identify unsuitable data.
- Compressed resources using algorithms other than zlib are not automatically decompressed.
- Native executable code is not reconstructed into original source code.

---

## License

Add an appropriate open-source license before distributing this project. The license determines the permissions other people have to use, modify, and redistribute your code.

---

## Author

Developed as a lightweight Python utility for Windows executable resource inspection and batch payload recovery.

Issues, bug reports, and improvements are welcome through GitHub Issues and Pull Requests.

**Inspect the file. Understand the payload. Never execute blindly.**
