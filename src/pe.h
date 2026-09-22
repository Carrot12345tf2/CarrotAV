#ifndef PE_H
#define PE_H
/* One PE section's raw file extent, as ClamAV measures it for .mdb
 * signatures: the section's bytes on disk, not its in-memory size. */
typedef struct { unsigned int raw, rsz; } PESECT;

/* Parse the section table from a buffer holding the start of a file.
 * Returns the number of sections written to out (0..max), or -1 if the
 * buffer isn't a PE file or the headers don't fit. filesize clamps sections
 * that claim to run past the end of the file. */
int pe_sections(const unsigned char *buf, unsigned int len, unsigned int filesize,
                PESECT *out, int max);
#endif
