CarrotAV 1.0 - lightweight antivirus for Windows XP (32-bit)
============================================================

81 KB executable. No .NET, no runtime, no service. Pure Win32 against the
Windows 5.1 API, PE subsystem version 4.0, links only against DLLs that
ship with XP (kernel32, user32, gdi32, comctl32, comdlg32, shell32,
shlwapi, advapi32, ole32, msvcrt).


WHAT IT DOES
------------
Scans
  Quick      memory + system32 + windows + temp + startup + Run keys
  Full       every fixed drive, hash matching on executable file types
  Deep       every fixed drive, full-file byte-pattern sweep + heuristics
  Folder     right-click a file, folder, drive, or empty space in any
             folder window / the desktop -> Scan with CarrotAV
  Memory     hashes the image of every running process
  Startup    everything referenced from Run/RunOnce and the Startup folders

Detection
  1. MD5 exact match against the signature database (binary search)
  2. Literal byte-pattern match, bucketed by first byte, with chunk-boundary
     overlap so a signature straddling a 64 KB read still fires
  3. Heuristics that need no signature at all:
       Heur.DoubleExtension     invoice.pdf.exe, photo.jpg.scr
       Heur.ExecInTempPath      PE dropped into Temp / TIF
       Heur.HiddenSystemExec    hidden+system .exe outside system32
       Heur.PackedHighEntropy   small PE with >7.4 bits/byte entropy
       Heur.ObfuscatedScript    vbs/js/hta with 2+ obfuscation markers
       Heur.AutorunInf          autorun.inf with open= / shellexecute=

Quarantine
  Detected files are XOR-masked (so they cannot execute) and moved into
  Quarantine\, with an index recording the original path and threat name.
  Restore and permanent delete are both supported. Locked files are
  scheduled for removal at next boot via MoveFileEx.

Live monitoring (Monitor tab)
  Three independent guards, all user-mode:
    file guard      ReadDirectoryChangesW over five hot trees at once -
                    the user profile, %TEMP%, system32, the common Startup
                    folder and common AppData. Anything created or modified
                    is hashed and heuristically checked, then quarantined.
    process guard   polls the process list every 2 seconds. Any image that
                    appears is scanned, and on a signature hit the process
                    is terminated (toggle with the "Kill procs" button).
    registry guard  RegNotifyChangeKeyValue on HKLM and HKCU Run keys.
                    Anything that adds itself to autostart is reported and
                    its target scanned - this is how most XP-era malware
                    persists, so it is worth watching directly.
  The tab shows a live event feed plus counters for files checked, threats
  blocked, new processes seen and autostart changes.

Firewall (Firewall tab)
  Driven through the XP SP2 firewall COM API (INetFwProfile), not netsh,
  so rules can actually be enumerated rather than scraped from console text.
    - turn the firewall on or off
    - "Block all exceptions" panic switch for untrusted networks
    - list every authorized program with its path, scope and allow/block
      state, and remove any rule
    - add a block rule for any program you pick
    - list every globally open port
    - "Harden ports" closes the legacy attack surface: 135, 137-139, 445,
      593, 1025 and 5000, TCP and UDP. Breaks file/printer sharing.
  If the COM objects will not instantiate, it falls back to netsh and the
  registry for basic on/off state.

Web shield (Web Shield tab)
  Imports a hosts-format blocklist into HOSTS inside a managed marker block,
  so your own entries are never touched and can be cleanly removed. Ships
  with 79,746 malware and adware domains. You can also add single domains.


BUILDING
--------
Cross-compile from Linux/WSL:
    sudo apt install gcc-mingw-w64-i686
    make

On Windows with MinGW, edit the first two lines of the Makefile to
    CC = gcc
    WINDRES = windres
then run mingw32-make.

Output: carrotav.exe


DEFINITIONS
-----------
No antivirus vendor licenses its signatures for redistribution. The one
freely available full-size set is ClamAV's, which is what this uses.

Run tools\get_defs.py on a MODERN machine (XP cannot negotiate TLS 1.2, so
it cannot reach database.clamav.net itself). No arguments needed - just:

    python get_defs.py

or double-click it on Windows. It downloads, unpacks, compiles and writes
carrot.cdb next to itself, then tells you where to put it. If the download
fails you can drop main.cvd and daily.cvd into the _clamav_cache folder by
hand and run it again; it will build from those without downloading.

build_defs.py is the same engine with command-line switches, if you want
finer control:

    python build_defs.py --download --out ..\defs\carrot.cdb

That downloads main.cvd and daily.cvd, unpacks them, and compiles:
  *.hdb/*.hsb/*.hdu  ->  MD5 hash records
  *.ndb              ->  literal byte patterns (wildcard sigs are skipped,
                         since the XP engine does plain memcmp)

Then copy defs\carrot.cdb to the CarrotAV folder on the XP box and use
Definitions -> Reload.

Size control:
    --max-patterns 50000   fewer patterns, less RAM
    --no-patterns          hash signatures only; smallest and fastest
                           (recommended if the XP machine has under 512 MB)

The whole database is loaded into RAM at startup. Roughly:
    hashes   24 bytes each
    patterns 10 bytes + pattern length
So ~1M hashes plus 200k patterns lands around 30-40 MB.


INSTALLER
---------
A ready-to-run installer is already built: dist\CarrotAV-1.0.0-Setup.exe
It bundles the scanner, the starter database, the 79,746-domain blocklist and
the definition tools. Just run it on the XP machine as an administrator.

To rebuild it yourself:
    makensis installer\carrotav.nsi          (NSIS 3.x, works on Linux too)

An Inno Setup script with the same behaviour is also included.
installer\carrotav.iss builds with Inno Setup 5.6.1 (the last release with
full Win9x/XP support) and produces a classic-wizard setup with component
selection, Start Menu group, desktop/Quick Launch icons, shell context-menu
integration, optional startup registration, and a proper uninstaller.

    ISCC.exe installer\carrotav.iss

If you have InstallShield, the mapping is direct: [Files] to the File
table, [Icons] to the Shortcut table, [Registry] to the Registry table,
and [Run]/[Code] to deferred custom actions.


TESTING IT WORKS
----------------
Save the EICAR string to a file (it is a harmless industry-standard test):

    X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

Run a Deep scan on that folder. It should report Eicar-Test-Signature.
The pattern is included in every database build_defs.py produces.


RIGHT-CLICK MENU
----------------
The installer registers "Scan with CarrotAV" in five places:

  right-click a file                 -> scans that file (always deep)
  right-click a folder               -> scans the folder and everything under it
  right-click empty space in a folder-> "Scan this folder with CarrotAV"
  right-click the desktop background -> scans the Desktop folder
  right-click a drive in My Computer -> scans the whole drive

Explorer passes the path as the first argument; CarrotAV opens, switches to
the Scan tab and starts immediately. Background verbs use %V (the folder being
viewed) rather than %1, which is empty for those verbs.

To remove just the menu without uninstalling, delete these keys:
  HKCR\*\shell\CarrotAV
  HKCR\Directory\shell\CarrotAV
  HKCR\Directory\Background\shell\CarrotAV
  HKCR\DesktopBackground\shell\CarrotAV
  HKCR\Drive\shell\CarrotAV
  HKCR\Folder\shell\CarrotAV


COMMAND LINE
------------
    carrotav.exe /quick
    carrotav.exe /full
    carrotav.exe /deep
    carrotav.exe "C:\path\to\file_or_folder"     scan that target
    carrotav.exe /importhosts "list.txt"          apply a blocklist, then exit
    carrotav.exe /clearhosts                      remove our HOSTS block, then exit


HONEST LIMITS
-------------
- Real-time protection is user-mode on-write scanning, not a kernel
  filter driver. It cannot block an execute that beats it to the punch.
  A true on-access blocker on XP needs a signed file system filter driver,
  which is a separate project an order of magnitude larger than this one.
- No archive unpacking. Files inside zip/rar/cab are matched by the
  archive's own hash only.
- Pattern matching is literal. ClamAV's wildcard, alternation and
  nibble-mask signatures are skipped by the compiler, so detection is
  weaker than ClamAV proper on polymorphic families.
- The firewall module drives the built-in XP firewall; it is not its own
  packet filter.
- Deep scans are I/O bound. On period hardware, budget hours for a full
  drive with patterns enabled.

Run as administrator: HOSTS edits, firewall changes and quarantining files
in Program Files all require it. The manifest requests it already.
