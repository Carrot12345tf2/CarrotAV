# CarrotAV

A lightweight antivirus for **Windows XP (32-bit)**. Pure Win32, no .NET, no
runtime — the scanner is a ~150 KB executable that links only against DLLs that
ship with XP itself.

Built as a hobby project. It is not a replacement for a maintained commercial
product on an internet-facing machine, but on a retro XP box it does real work:
signature and heuristic scanning, live monitoring, a firewall front-end, a web
shield, archive-bomb detection, system-file integrity checking, and — unusually
for XP — the ability to download and compile fresh virus definitions directly on
the machine over modern TLS.

## Features

- **Scanning** — quick, full, deep (byte-pattern), single-file, memory, and
  startup scans. Right-click any file, folder, drive, or the desktop to scan it.
- **Detection** — MD5 hash matching against a compiled ClamAV database, literal
  byte-pattern matching, and signature-free heuristics (packers, double
  extensions, temp-dropped executables, obfuscated scripts, autorun.inf).
- **Live monitoring** — three user-mode guards: a file-system watcher, a process
  guard that scans new process images, and a registry guard that catches
  autostart changes.
- **System integrity** — snapshot every system binary; verified files are
  path-bound, so a real infection still shows even on a baselined file, and
  modified system files can be repaired from Windows' own `dllcache`/`i386`.
- **Firewall** — controls the built-in XP firewall through its COM API: toggle
  it, block programs, list and close open ports.
- **Web shield** — imports a hosts-format blocklist (ships with ~79k domains)
  inside a managed marker block, so your own HOSTS entries are never touched.
- **Archive-bomb guard** — reads a zip's manifest without extracting and refuses
  ratio bombs, recursive (42.zip-style) bombs, entry floods, and zip-slip.
- **Tray + balloons** — runs in the background from the tray with restrained,
  non-nagging notifications. Closing the window keeps the shield running.
- **Online definition updates** — `defupdate.exe` bundles its own TLS 1.2
  (mbedTLS) so it can download and compile definitions from the XP machine
  itself, with no second computer and no Python.

## Downloading

Grab the latest installer from the [**Releases**](../../releases) page and run
it on the XP machine as an administrator. It bundles the scanner, a starter
database, the definition tools, and the web-shield blocklist.

## Building from source

Cross-compile from Linux/WSL with the mingw-w64 toolchain:

```bash
sudo apt install gcc-mingw-w64-i686
make
```

Output: `carrotav.exe`. Build the installer with NSIS:

```bash
makensis installer/carrotav.nsi
```

## Virus definitions

Definitions are compiled from ClamAV's freely-redistributable database.

- **On the XP machine:** click **Definitions → Update Online**. This runs
  `tools/defupdate.exe`, which connects to ClamAV over TLS 1.2, downloads the
  databases, and compiles `carrot.cdb` locally.
- **On any modern PC:** run `tools/get_defs.py` (needs Python 3) and copy the
  resulting `carrot.cdb` into the XP machine's `defs` folder.

The bundled TLS stack needs an occasional refresh as internet certificates and
ciphers rotate — see [`tools/UPDATING_TLS.txt`](tools/UPDATING_TLS.txt).

## Repository layout

```
src/          the scanner — C source, resources, manifest, icon
installer/    NSIS and Inno Setup installer scripts
tools/        definition builders, the online updater, CA bundle, docs
updater/      defupdate.exe source (mbedTLS-based TLS 1.2 downloader)
defs/         the web-shield blocklist (compiled defs are not committed)
```

## License

Public domain, except third-party components under their own licenses (ClamAV
signatures are GPL; mbedTLS is Apache 2.0).
