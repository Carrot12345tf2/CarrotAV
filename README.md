# CarrotAV

This is a simple, lightweight anti-virus for Windows XP™

I created this anti-virus because I myself, have an old xp machine. I was tired of 
constantly looking for modern anti-viruses that would work on it to keep it safe.
So, I decided to create my own.

## Features

- **Scanning** — There are 4 different modes of scanning, quick, full, deep, and custom.
Quick provides an accurate fast scan that utilizes a small amount of resources. Full provides an in-depth scan 
that is balanced and speedy. Deep on the other hand, will find those sneaky viruses that maybe be really hiding,
it checks every file and folder. Finally, custom, you can either right click on or in a file/folder then press "scan with
CarrotAV" to instantly open up CarrotAV and scan those folders.

- **Detection** — This program uses MD5 hash matching against a compiled ClamAV database, actual byte-pattern matching, and wonderful signature-
filled heuristics. This heuristic checking includes but is not limited to: packers, double extensions, temp-dropped executables,
objuscated scripts, and autorun.inf(s).
  
- **Live monitoring** — There are three user-mode guards: a file-system watcher, a process
  guard that scans new process images, and a registry guard that catches
  autostart changes.
  
- **System integrity** — There is the option to snapshot every system binary; verified files are
  path-bound, so a real infection still shows even on a baselined file, and
  modified system files can be repaired from Windows' own `dllcache`/`i386`.
  
- **Firewall** — This program controls the built-in XP firewall through it's COM API, you can toggle
  it, block programs, and list and close open ports.
  
- **Web shield** — This software also imports a hosts-format blocklist (ships with about 79k domains)
  inside a managed marker block, so your own entries are never touched.
  
- **Archive-bomb guard** — This software is equipped for every situation, it can read a zip's manifest without extracting and refuses
  ratio bombs, recursive (42.zip-style) bombs, entry floods, and zip-slip files.
  
- **Tray + balloons** — This program also runs in the background from the tray with restrained,
  non-nagging notifications. The shield keeps running even if the program window is closed.
  
- **Online definition updates** — `defupdate.exe` bundles its own TLS 1.2
  (mbedTLS) so it can download and compile definitions from the XP machine
  itself, with no second computer and no Python.

## Heads Up 

This project IS vibe-coded, but I can personally confirm that these features WORK. I will try my best to keep this program up-to-date and working.
Thank you.

## Downloading

You can grab the latest installer from the [**Releases**](../../releases) page and run
it on the XP machine to install it. It bundles the scanner, a starter
database, the definition tools, and the web-shield blocklist.

## Building from source

Cross-compile from Linux/WSL with the mingw-w64 toolchain:

bash
sudo apt install gcc-mingw-w64-i686
make


Output: `carrotav.exe`. Build the installer with NSIS:

bash
makensis installer/carrotav.nsi


## Virus definitions

Definitions are compiled from ClamAV's freely-redistributable database.

- **On the XP machine:** click **Definitions → Update Online**. This runs
  `tools/defupdate.exe`, which connects to ClamAV over TLS 1.2, downloads the
  databases, and compiles `carrot.cdb` locally.
- **On any modern PC:** run `tools/get_defs.py` (needs Python 3) and copy the
  resulting `carrot.cdb` into the XP machine's `defs` folder.

The bundled TLS stack needs an occasional refresh as internet certificates and
ciphers rotate — see [`tools/UPDATING_TLS.txt`](tools/UPDATING_TLS.txt).

## License

Public domain, except third-party components under their own licenses (ClamAV
signatures are GPL; mbedTLS is Apache 2.0).
