#!/usr/bin/env python3
"""
get_defs.py  --  CarrotAV definition fetcher.

Just run it. No arguments, no setup, standard library only.

    python get_defs.py           (or double-click it on Windows)

It downloads the ClamAV signature databases, compiles them into a single
carrot.cdb sitting next to this script, and tells you what to do with it.
Send that carrot.cdb back and drop it in CarrotAV\\defs\\.

Run this on a modern machine. Windows XP cannot negotiate TLS 1.2, so it
cannot reach the ClamAV servers itself.

ClamAV signatures are GPL-licensed.
"""

import gzip, io, os, re, ssl, struct, sys, tarfile, time, urllib.request

HERE     = os.path.dirname(os.path.abspath(__file__))
OUT      = os.path.join(HERE, "carrot.cdb")
WORK     = os.path.join(HERE, "_clamav_cache")

MIRRORS  = ["https://database.clamav.net/{}", "http://database.clamav.net/{}"]
WANT     = ["main.cvd", "daily.cvd"]

MAGIC        = b"CAVD"
FORMAT_VER   = 1
MIN_PAT      = 32       # shorter literals produce false-positive floods
MAX_PAT      = 256     # must match MAX_PAT in av.h
MAX_PATTERNS = 0        # ndb patterns are offset/target-anchored in ClamAV;
                       # matching them unanchored causes mass false positives # keeps XP memory use sane
NOT_HEX      = re.compile(rb"[^0-9a-fA-F]")


# ----------------------------------------------------------------- helpers
def say(msg=""):
    print(msg, flush=True)


def bar(done, total, width=38):
    if not total:
        return f"  {done/1048576:6.1f} MB"
    filled = int(width * done / total)
    return (f"  [{'#'*filled}{'.'*(width-filled)}] "
            f"{done/1048576:6.1f}/{total/1048576:.1f} MB")


def fetch(name):
    """Download one CVD, resuming nothing, retrying across mirrors."""
    dest = os.path.join(WORK, name)

    # reuse a copy from today rather than pulling 200 MB again
    if os.path.exists(dest) and time.time() - os.path.getmtime(dest) < 43200:
        say(f"  {name}: using cached copy from earlier today")
        return dest

    ctx = ssl.create_default_context()
    for url in MIRRORS:
        u = url.format(name)
        try:
            say(f"  {name}: connecting to {u.split('/')[2]}...")
            req = urllib.request.Request(u, headers={"User-Agent": "CarrotAV/1.0"})
            with urllib.request.urlopen(req, timeout=120, context=ctx) as r:
                total = int(r.headers.get("Content-Length") or 0)
                done = 0
                tmp = dest + ".part"
                with open(tmp, "wb") as f:
                    while True:
                        chunk = r.read(1 << 18)
                        if not chunk:
                            break
                        f.write(chunk)
                        done += len(chunk)
                        print("\r" + bar(done, total), end="", flush=True)
                print()
            os.replace(tmp, dest)
            return dest
        except Exception as e:
            say(f"    failed: {e}")
    return None


def unpack(path):
    """A .cvd is a 512-byte ASCII header followed by a gzipped tar."""
    with open(path, "rb") as f:
        header, body = f.read(512), f.read()

    if not header.startswith(b"ClamAV-VDB:"):
        say(f"  {os.path.basename(path)}: not a CVD file, skipping")
        return

    fields = header.decode("ascii", "replace").split(":")
    say(f"  {os.path.basename(path)}: built {fields[1]}, "
        f"version {fields[2]}, {fields[3]} signatures")

    try:
        raw = gzip.decompress(body)
    except OSError:
        raw = body

    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for m in tf.getmembers():
            if m.isfile() and m.name.lower().endswith(
                    (".hdb", ".hsb", ".hdu", ".ndb")):
                with open(os.path.join(WORK, os.path.basename(m.name)), "wb") as f:
                    f.write(tf.extractfile(m).read())


def parse_hashes(path, out):
    """hdb/hsb line:  <digest>:<size>:<name>"""
    n = 0
    with open(path, "rb") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            parts = line.split(b":")
            if len(parts) < 3 or len(parts[0]) != 32:   # MD5 only
                continue
            try:
                digest = bytes.fromhex(parts[0].decode("ascii"))
            except ValueError:
                continue
            try:
                size = 0 if parts[1] == b"*" else int(parts[1])
                if size > 0xFFFFFFFF:
                    size = 0
            except ValueError:
                size = 0
            out.append((digest, size, parts[2].decode("ascii", "replace")[:100]))
            n += 1
    return n


def parse_patterns(path, out):
    """ndb line: <name>:<target>:<offset>:<hexsig>. Literal signatures only -
    the XP engine does plain memcmp, so wildcard sigs are dropped."""
    n = 0
    with open(path, "rb") as f:
        for line in f:
            if len(out) >= MAX_PATTERNS:
                break
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            parts = line.split(b":")
            if len(parts) < 4:
                continue
            hexsig = parts[3]
            if NOT_HEX.search(hexsig) or len(hexsig) % 2:
                continue
            if len(hexsig) // 2 < MIN_PAT:
                continue
            hexsig = hexsig[:MAX_PAT * 2]
            try:
                raw = bytes.fromhex(hexsig.decode("ascii"))
            except ValueError:
                continue
            out.append((raw, parts[0].decode("ascii", "replace")[:100]))
            n += 1
    return n


def compile_db(hashes, patterns):
    seen, uniq = set(), []
    for h, size, name in hashes:
        if (h, size) in seen:
            continue
        seen.add((h, size))
        uniq.append((h, size, name))
    uniq.sort(key=lambda r: r[0])          # client binary-searches this

    names, offsets = bytearray(), {}

    def intern(text):
        b = text.encode("ascii", "replace") + b"\0"
        if b not in offsets:
            offsets[b] = len(names)
            names.extend(b)
        return offsets[b]

    hash_recs = bytearray()
    for h, size, name in uniq:
        hash_recs += struct.pack("<16sII", h, size, intern(name))

    blob, pat_recs = bytearray(), bytearray()
    for raw, name in patterns:
        pat_recs += struct.pack("<HII", len(raw), len(blob), intern(name))
        blob.extend(raw)

    with open(OUT, "wb") as f:
        f.write(struct.pack("<4sIIIIII", MAGIC, FORMAT_VER, len(uniq),
                            len(patterns), len(blob), len(names), int(time.time())))
        f.write(hash_recs)
        f.write(pat_recs)
        f.write(blob)
        f.write(names)

    return len(uniq), len(patterns), len(blob), len(names)


# -------------------------------------------------------------------- main
def main():
    say()
    say("  CarrotAV definition builder")
    say("  " + "=" * 44)
    say()

    os.makedirs(WORK, exist_ok=True)

    say("Step 1 of 3 - downloading ClamAV databases")
    got = 0
    for name in WANT:
        path = fetch(name)
        if path:
            unpack(path)
            got += 1
    if not got:
        # Maybe the signature files are already sitting in the cache, either
        # from an earlier run or dropped in by hand. Use them if so.
        have = [f for f in os.listdir(WORK)
                if f.lower().endswith((".hdb", ".hsb", ".hdu", ".ndb", ".cvd"))]
        for f in [x for x in have if x.lower().endswith(".cvd")]:
            unpack(os.path.join(WORK, f))
        have = [f for f in os.listdir(WORK)
                if f.lower().endswith((".hdb", ".hsb", ".hdu", ".ndb"))]
        if not have:
            say()
            say("  Could not download anything.")
            say("  Check the internet connection, or grab main.cvd and daily.cvd")
            say("  manually from https://database.clamav.net/ and drop them into:")
            say(f"    {WORK}")
            say("  then run this again - it will use them without downloading.")
            return 1
        say()
        say(f"  Download failed, but {len(have)} signature file(s) are already")
        say("  cached. Building from those instead.")

    say()
    say("Step 2 of 3 - parsing signatures")
    hashes, patterns = [], []
    for fn in sorted(os.listdir(WORK)):
        p = os.path.join(WORK, fn)
        if not os.path.isfile(p):
            continue
        low = fn.lower()
        if low.endswith((".hdb", ".hsb", ".hdu")):
            say(f"  {fn}: {parse_hashes(p, hashes):,} hashes")
        elif low.endswith(".ndb") and MAX_PATTERNS:
            say(f"  {fn}: {parse_patterns(p, patterns):,} literal patterns")
        elif low.endswith(".ndb"):
            say(f"  {fn}: skipped (offset-anchored patterns cause false positives)")

    # EICAR, so the install can always be verified end to end
    patterns.append((b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
                     b"ANTIVIRUS-TEST-FILE!$H+H*"[:MAX_PAT],
                     "Eicar-Test-Signature"))

    if not hashes and not patterns:
        say("  Nothing parsed. The downloads may be corrupt - delete")
        say(f"  {WORK} and run this again.")
        return 1

    say()
    say("Step 3 of 3 - compiling carrot.cdb")
    nh, np, blob, nb = compile_db(hashes, patterns)
    size = os.path.getsize(OUT)
    ram = (nh * 24 + np * 10 + blob + nb) / 1048576

    say()
    say("  " + "=" * 44)
    say(f"  Done.  {OUT}")
    say()
    say(f"    {nh:,} hash signatures")
    say(f"    {np:,} pattern signatures")
    say(f"    {size/1048576:.1f} MB on disk")
    say(f"    ~{ram:.0f} MB RAM once loaded on the XP machine")
    say("  " + "=" * 44)
    say()
    say("  Next: copy carrot.cdb into the CarrotAV\\defs\\ folder on the XP")
    say("  box (replacing the starter file), then open CarrotAV and choose")
    say("  Definitions -> Reload.")
    say()
    if ram > 180:
        say("  That is a big database. If the XP machine has under 512 MB of")
        say("  RAM, edit MAX_PATTERNS near the top of this script down to")
        say("  50000 and run it again for a lighter build.")
        say()
    say(f"  The {os.path.basename(WORK)} folder is just a cache - safe to delete.")
    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    except KeyboardInterrupt:
        say("\n  Cancelled.")
    except Exception as e:
        say(f"\n  Unexpected error: {e}")
    # keep the console open when double-clicked on Windows
    if os.name == "nt" and sys.stdin and sys.stdin.isatty():
        try:
            input("  Press Enter to close...")
        except EOFError:
            pass
    sys.exit(code)
