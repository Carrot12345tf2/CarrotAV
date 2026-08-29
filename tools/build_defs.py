#!/usr/bin/env python3
"""
build_defs.py - compile ClamAV signatures into a CarrotAV .cdb database.

Run this on a modern machine (XP can't do TLS 1.2), then copy the resulting
carrot.cdb to the XP box's CarrotAV\\defs\\ folder.

    python build_defs.py --download --out carrot.cdb
    python build_defs.py --from-dir ./clamdb --out carrot.cdb
    python build_defs.py --download --max-patterns 150000 --out carrot.cdb

What gets used:
  *.hdb / *.hsb / *.hdu   MD5 file hashes          -> exact-match records
  *.ndb                   body-based hex patterns  -> byte-pattern records
                          (only literal patterns; wildcards are skipped
                           because the XP engine does plain memcmp)

ClamAV signatures are GPL-licensed. Redistribute the compiled database only
under terms compatible with that.
"""

import argparse, gzip, io, os, re, struct, sys, tarfile, time, urllib.request

MIRRORS = [
    "https://database.clamav.net/{}",
    "http://database.clamav.net/{}",
]
CVDS = ["main.cvd", "daily.cvd", "bytecode.cvd"]

MAGIC       = b"CAVD"
VERSION     = 1
MIN_PAT     = 32      # shorter literals cause floods of false positives
MAX_PAT     = 256    # must match MAX_PAT in av.h
WILDCARD    = re.compile(rb"[^0-9a-fA-F]")


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def download(name, dest_dir):
    dest = os.path.join(dest_dir, name)
    for m in MIRRORS:
        url = m.format(name)
        try:
            log(f"  fetching {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "CarrotAV/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
                total = 0
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
                    total += len(chunk)
            log(f"  saved {name} ({total/1048576:.1f} MB)")
            return dest
        except Exception as e:
            log(f"  failed: {e}")
    return None


def unpack_cvd(path, out_dir):
    """A .cvd is a 512-byte ASCII header followed by a gzipped tar."""
    with open(path, "rb") as f:
        header = f.read(512)
        body = f.read()
    if not header.startswith(b"ClamAV-VDB:"):
        log(f"  {path}: not a CVD, skipping")
        return
    fields = header.decode("ascii", "replace").split(":")
    log(f"  {os.path.basename(path)}: built {fields[1]}, version {fields[2]}, "
        f"{fields[3]} signatures")
    try:
        raw = gzip.decompress(body)
    except OSError:
        raw = body
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if not m.name.lower().endswith((".hdb", ".hsb", ".hdu", ".ndb", ".mdb")):
                continue
            data = tf.extractfile(m).read()
            with open(os.path.join(out_dir, os.path.basename(m.name)), "wb") as f:
                f.write(data)


def parse_hash_db(path, hashes):
    """hdb line: <md5>:<size>:<name>   hsb line: <sha256>:<size>:<name>"""
    n = 0
    with open(path, "rb") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            parts = line.split(b":")
            if len(parts) < 3:
                continue
            digest, size, name = parts[0], parts[1], parts[2]
            if len(digest) != 32:          # MD5 only; the engine hashes MD5
                continue
            try:
                raw = bytes.fromhex(digest.decode("ascii"))
            except ValueError:
                continue
            try:
                sz = 0 if size == b"*" else int(size)
                if sz > 0xFFFFFFFF:
                    sz = 0
            except ValueError:
                sz = 0
            hashes.append((raw, sz, name.decode("ascii", "replace")[:100]))
            n += 1
    return n


def parse_ndb(path, pats, limit):
    """ndb line: <name>:<target>:<offset>:<hexsig>[:min:max]"""
    n = 0
    with open(path, "rb") as f:
        for line in f:
            if len(pats) >= limit:
                break
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            parts = line.split(b":")
            if len(parts) < 4:
                continue
            name, hexsig = parts[0], parts[3]
            # skip anything with wildcards, alternates or nibble masks -
            # the XP engine does literal memcmp only
            if WILDCARD.search(hexsig):
                continue
            if len(hexsig) % 2:
                continue
            blen = len(hexsig) // 2
            if blen < MIN_PAT:
                continue
            if blen > MAX_PAT:
                hexsig = hexsig[: MAX_PAT * 2]
                blen = MAX_PAT
            try:
                raw = bytes.fromhex(hexsig.decode("ascii"))
            except ValueError:
                continue
            pats.append((raw, name.decode("ascii", "replace")[:100]))
            n += 1
    return n


def build(hashes, pats, out_path):
    # de-duplicate and sort hashes so the client can binary-search
    seen = set()
    uniq = []
    for h, sz, nm in hashes:
        key = (h, sz)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((h, sz, nm))
    uniq.sort(key=lambda x: x[0])

    names = bytearray()
    name_off = {}

    def intern(s):
        b = s.encode("ascii", "replace") + b"\0"
        if b in name_off:
            return name_off[b]
        off = len(names)
        names.extend(b)
        name_off[b] = off
        return off

    hash_recs = bytearray()
    for h, sz, nm in uniq:
        hash_recs += struct.pack("<16sII", h, sz, intern(nm))

    patblob = bytearray()
    pat_recs = bytearray()
    for raw, nm in pats:
        off = len(patblob)
        patblob.extend(raw)
        pat_recs += struct.pack("<HII", len(raw), off, intern(nm))

    hdr = struct.pack("<4sIIIIII", MAGIC, VERSION, len(uniq), len(pats),
                      len(patblob), len(names), int(time.time()))

    with open(out_path, "wb") as f:
        f.write(hdr)
        f.write(hash_recs)
        f.write(pat_recs)
        f.write(patblob)
        f.write(names)

    size = os.path.getsize(out_path)
    log("")
    log(f"  wrote {out_path}")
    log(f"    {len(uniq):,} hash signatures")
    log(f"    {len(pats):,} pattern signatures")
    log(f"    {size/1048576:.1f} MB on disk")
    log(f"    approx {(len(uniq)*24 + len(pats)*10 + len(patblob) + len(names))/1048576:.1f} MB RAM when loaded")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true",
                    help="fetch main.cvd and daily.cvd from database.clamav.net")
    ap.add_argument("--from-dir", metavar="DIR",
                    help="use .hdb/.ndb files already present in DIR")
    ap.add_argument("--out", default="carrot.cdb")
    ap.add_argument("--max-patterns", type=int, default=200000,
                    help="cap pattern count to keep XP memory use sane")
    ap.add_argument("--no-patterns", action="store_true",
                    help="hash signatures only (smallest, fastest)")
    ap.add_argument("--work", default="clamdb_work")
    args = ap.parse_args()

    work = args.from_dir or args.work
    os.makedirs(work, exist_ok=True)

    if args.download:
        log("Downloading ClamAV databases...")
        for name in CVDS[:2]:
            p = download(name, work)
            if p:
                unpack_cvd(p, work)

    hashes, pats = [], []
    files = sorted(os.listdir(work))
    if not files:
        log("No signature files found. Use --download or --from-dir.")
        return 1

    log("\nParsing signature files...")
    for fn in files:
        p = os.path.join(work, fn)
        if not os.path.isfile(p):
            continue
        low = fn.lower()
        if low.endswith((".hdb", ".hsb", ".hdu")):
            n = parse_hash_db(p, hashes)
            log(f"  {fn}: {n:,} hashes")
        elif low.endswith(".ndb") and not args.no_patterns:
            n = parse_ndb(p, pats, args.max_patterns)
            log(f"  {fn}: {n:,} literal patterns")

    # always include EICAR so the install can be verified
    eicar = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
             b"ANTIVIRUS-TEST-FILE!$H+H*")
    if not args.no_patterns:
        pats.append((eicar[:MAX_PAT], "Eicar-Test-Signature"))

    if not hashes and not pats:
        log("Nothing parsed - is the work directory correct?")
        return 1

    build(hashes, pats, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
