/* pe.c - minimal, bounds-checked PE section table reader.
 *
 * Only what engine 2.0 needs for ClamAV .mdb (PE section MD5) signatures:
 * where each section's raw bytes are and how many there are. Written as
 * plain C with no OS calls so it can be tested anywhere, and so a malformed
 * header can only ever produce "not a PE", never a read outside the buffer.
 *
 * Offsets and sizes follow ClamAV's own measurement: raw offset rounded DOWN
 * and raw size rounded UP to the file alignment, then clamped to the file.
 * For normal files (0x200 alignment, aligned sections) that is simply
 * PointerToRawData and SizeOfRawData.
 */
#include "pe.h"

static unsigned int u16(const unsigned char *p) { return p[0] | (p[1] << 8); }
static unsigned int u32(const unsigned char *p)
{ return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int)p[3] << 24); }

int pe_sections(const unsigned char *buf, unsigned int len, unsigned int filesize,
                PESECT *out, int max)
{
    unsigned int e_lfanew, nsect, optsz, tbl, falign, i, n = 0;

    if (len < 64 || buf[0] != 'M' || buf[1] != 'Z') return -1;
    e_lfanew = u32(buf + 0x3C);
    /* PE signature (4) + COFF file header (20) must fit */
    if (e_lfanew > len || len - e_lfanew < 24) return -1;
    if (buf[e_lfanew] != 'P' || buf[e_lfanew+1] != 'E' ||
        buf[e_lfanew+2] != 0  || buf[e_lfanew+3] != 0) return -1;

    nsect = u16(buf + e_lfanew + 6);
    optsz = u16(buf + e_lfanew + 20);
    if (nsect == 0 || nsect > 96) return -1;

    /* FileAlignment sits at offset 36 of the optional header in both PE32
     * and PE32+. Only trust it if it's a sane power of two. */
    falign = 0;
    if (optsz >= 40 && e_lfanew + 24 + 40 <= len) {
        falign = u32(buf + e_lfanew + 24 + 36);
        if (falign < 0x200 || falign > 0x10000 || (falign & (falign - 1))) falign = 0;
    }

    tbl = e_lfanew + 24 + optsz;
    if (tbl > len || (len - tbl) / 40 < nsect) return -1;   /* table must fit */

    for (i = 0; i < nsect && (int)n < max; i++) {
        const unsigned char *s = buf + tbl + i * 40;
        unsigned int rsz = u32(s + 16), raw = u32(s + 20);
        if (falign) {
            raw &= ~(falign - 1);                               /* round down */
            if (rsz > 0xFFFFFFFFu - falign) continue;
            rsz = (rsz + falign - 1) & ~(falign - 1);           /* round up   */
        }
        if (rsz == 0 || raw >= filesize) continue;
        if (rsz > filesize - raw) rsz = filesize - raw;          /* clamp */
        out[n].raw = raw;
        out[n].rsz = rsz;
        n++;
    }
    return (int)n;
}
