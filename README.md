# CarrotAV

This is a simple, lightweight anti-virus for Windows XP™ and Windows 2000™

I created this anti-virus because I myself, have an old xp machine. I was tired of 
constantly looking for modern anti-viruses that would work on it to keep it safe.
So, I decided to create my own.

## Features

- **Scanning** — There are 4 different modes of scanning, quick, full, deep, and custom.
Quick provides an accurate fast scan that utilizes a small amount of resources. Full provides an in-depth scan 
that is balanced and speedy. Deep on the other hand, will find those sneaky viruses that maybe be really hiding,
it checks every file and folder. Finally, custom, you can either right click on or in a file/folder then press "scan with
CarrotAV" to instantly open up CarrotAV and scan those folders.

- **Detection** — CarrotAV Engine 2.0 matches files against a compiled ClamAV database using MD5 and SHA-256
file hashes, plus PE section hashes that catch repacked variants of known malware. On top of that are
signature-free heuristics, including but not limited to: packers, double extensions, temp-dropped executables,
obfuscated scripts, and autorun.inf(s).

- **Fewer false positives** — Files genuinely signed by Microsoft (or listed in a Windows catalog) are
verified with Windows itself, so a bad signature can't get a real Windows file quarantined. Signed files
also skip heuristics.
  
- **Live monitoring** — There are three user-mode guards: a file-system watcher, a process
  guard that scans new process images, and a registry guard that catches
  autostart changes.
  
- **System integrity** — There is the option to snapshot every system binary; verified files are
  path-bound, so a real infection still shows even on a baselined file, and
  modified system files can be repaired from Windows' own `dllcache`/`i386`.
  
- **Firewall** — On XP, this program controls the built-in firewall through it's COM API, you can toggle
  it, block programs, and list and close open ports. On Windows 2000, it uses the built-in
  TCP/IP filtering to control which inbound ports are allowed.
  
- **Web shield** — This software also imports a hosts-format blocklist (ships with about 90k domains from
  StevenBlack and The Block List Project) inside a managed marker block, so your own entries are never touched.
  
- **Archive-bomb guard** — This software is equipped for every situation, it can read a zip's manifest without extracting and refuses
  ratio bombs, recursive (42.zip-style) bombs, entry floods, and zip-slip files.
  
- **Tray + balloons** — This program also runs in the background from the tray with restrained,
  non-nagging notifications. The shield keeps running even if the program window is closed.

- **Themes** — On XP, pick between Classic, Aero, Green, and Autumn in Options → Theme.
  
- **Online definition updates** — `defupdate.exe` bundles its own TLS 1.2
  (mbedTLS) so it can download and compile definitions from the XP or 2000 machine
  itself, with no second computer and no Python.

## Heads Up 

This project IS vibe-coded, but I can personally confirm that these features WORK. I will try my best to keep this program up-to-date and working.
Thank you.

## Downloading

You can grab the latest installer from the [**Releases**](../../releases) page and run
it on the XP or 2000 machine to install it. It bundles the scanner, a starter
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

- **On the XP or 2000 machine:** go to the **Definitions** tab and click **Check for updates**. This runs
  `tools/defupdate.exe`, which connects to Microsoft's ClamAV definition mirror over TLS 1.2, downloads the
  databases, and compiles `carrot.cdb` locally. It also checks GitHub for a newer version of CarrotAV.
- **On any modern PC:** run `tools/get_defs.py` (needs Python 3) and copy the
  resulting `carrot.cdb` into the machine's `defs` folder.

The bundled TLS stack needs an occasional refresh as internet certificates and
ciphers rotate — see [`tools/UPDATING_TLS.txt`](tools/UPDATING_TLS.txt).

## License

GPL-3.0, third-party components under their own licenses (ClamAV
signatures are GPL; mbedTLS is Apache 2.0; The Block List Project is Unlicense).