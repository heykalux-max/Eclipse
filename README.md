# ECLIPSE

![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB)
![License MIT](https://img.shields.io/badge/license-MIT-green)

Open source threat scanner for Windows with a desktop interface (PySide6). It analyzes files, links, processes, startup programs and network connections, and always explains **why** something is considered dangerous.

> **Note:** Eclipse is an independent project based on heuristic analysis. It is useful as a second opinion, but it does not replace a certified antivirus (such as Microsoft Defender): keep that running alongside Eclipse.

## Download

**[⬇ Download Eclipse.exe](https://github.com/heykalux-max/Eclipse/raw/main/release/Eclipse.exe)** (Windows 10/11, 64-bit, version 1.1.0)

A single file, no installation: put it in a folder of your choice and run it. The `data`, `Quarantine` and `Reports` folders are created next to the executable.

> Windows SmartScreen may show "Windows protected your PC" because the executable is not digitally signed yet: click **More info → Run anyway**. If you prefer, you can build it yourself from source (see [Build](#build-single-executable)).

## Features

- **File and link scanning**: heuristic analysis of PE executables, scripts, archives and documents, with a SAFE / SUSPICIOUS / DANGEROUS verdict and an explanation of the reasons.
- **System Scan**: Quick, Full or Custom scan of the PC, multi-process, with caching and digital signature verification (Authenticode) to reduce false positives.
- **Script deobfuscation**: unpacks Base64 / `-EncodedCommand`, gzip/deflate, string concatenation, char codes, escapes, reversed strings and variable tricks in PowerShell, batch, VBScript, JavaScript and macros, then re-analyzes the hidden code.
- **AMSI scanning**: scripts, macros, decoded payloads and files inside archives are also checked in memory by the installed antivirus through the Windows Antimalware Scan Interface.
- **Real-time protection**: monitoring of high-risk folders (Downloads, Desktop, Temp…).
- **Ransomware shield**: decoy files and burst detection in Documents, Desktop and Pictures; a program that starts encrypting or destroying files is frozen and you choose whether to terminate it.
- **Processes**: list of running processes with analysis and the option to terminate them. **Memory scan** looks for injected code, threads started from unbacked memory and process hollowing.
- **Startup**: review of startup entries (registry, Startup folders, scheduled tasks).
- **Network**: active connections per process, with reverse DNS and suspicious ports.
- **Quarantine and exportable reports**.

## Privacy

File analysis happens on your PC: files, quarantine and reports stay in the local folders next to the executable and are never uploaded. Eclipse uses the network only in these cases:

- **VirusTotal (optional)**: if you enter your own API key, it sends VirusTotal the SHA-256 hash of analyzed files (not the file itself) and the addresses of the links you check.
- **Phishing lists**: it downloads public lists of known phishing sites (OpenPhish, Phishing.Database).
- **Link analysis**: it resolves the domain and contacts the site to follow redirects and read the page.
- **Network**: reverse DNS lookups for active connections.

## Running from source

Requirements:

- Windows 10/11
- Python 3.14

```powershell
git clone https://github.com/heykalux-max/Eclipse.git
cd Eclipse
pip install -r requirements.txt
python src\main.py
```

Command-line options:

| Option | Effect |
|---|---|
| `--tray` | start minimized to the notification area |
| `--quick-scan` | start a quick system scan right away |

## Build (single executable)

Requires Visual Studio Build Tools (MSVC).

```powershell
pip install nuitka zstandard
.\build.ps1
```

The executable is created in `dist\Eclipse.exe`. To keep intermediate files out of OneDrive, use `.\build.ps1 -BuildDir C:\temp\ecl`.

## Project structure

| File | Contents |
|---|---|
| `src/main.py` | graphical interface and startup |
| `src/engine.py` | file and link analysis engine |
| `src/fullscan.py` | System Scan (multi-process, caching, false-positive policy) |
| `src/sysmon.py` | processes, network, startup, digital signatures |
| `src/deobf.py` | script deobfuscation (normalisers and decoders) |
| `src/amsi.py` | Windows AMSI in-memory scanning |
| `src/memscan.py` | process memory scanner (injection, hollowing) |
| `src/ransomguard.py` | anti-ransomware behaviour shield |
| `src/make_icon.py` | generates `eclipse.ico` / `eclipse.png` |
| `release/Eclipse.exe` | latest compiled version, for direct download |

The `data/`, `Quarantine/` and `Reports/` folders hold the user's local data and are excluded from the repository via `.gitignore`.

## Contributing

Contributions, bug reports and ideas are welcome.

- **Bugs or false positives**: open an [issue](https://github.com/heykalux-max/Eclipse/issues) with your Windows version, the file or process involved (name and SHA-256 hash, never the file itself if it is malware) and the verdict you got.
- **Code**: fork the repo, create a branch for your change and open a pull request with a short description of what it changes and how you tested it.
- **Security vulnerabilities** in Eclipse itself: do not open a public issue, use GitHub's [Report a vulnerability](https://github.com/heykalux-max/Eclipse/security/advisories/new) feature.

## License

Released under the [MIT](LICENSE) license: you can use, modify and redistribute it freely, as long as you keep the copyright notice.

Eclipse uses third-party libraries under their own licenses: [PySide6](https://doc.qt.io/qtforpython-6/licenses.html) (LGPL v3), [pefile](https://github.com/erocarrera/pefile) (MIT) and [psutil](https://github.com/giampaolo/psutil) (BSD-3-Clause).
