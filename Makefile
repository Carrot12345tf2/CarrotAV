# CarrotAV - build with mingw-w64 (i686) or MinGW on Windows
CC      = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres
CFLAGS  = -O2 -municode -mwindows -Wall -Wextra -Wno-unused-parameter \
          -fno-ident -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--gc-sections -s -static-libgcc
LIBS    = -loleaut32 -luuid -lcomctl32 -lshlwapi -lshell32 -lole32 -ladvapi32 -lcomdlg32 -lgdi32 \
          -luser32 -lkernel32 -lm

SRC = src/main.c src/scan.c src/sigdb.c src/protect.c src/fw.c src/realtime.c src/baseline.c src/archive.c src/compat.c src/fw2k.c src/engine.c src/sha256.c src/pe.c src/trust.c src/zipscan.c src/devguard.c src/wsc.c src/autorun.c src/report.c
# zlib's inflate half, vendored (zlib licence in src/zlib/LICENSE) so a plain
# "make" needs nothing beyond the mingw compiler. Used to scan inside ZIPs.
ZSRC = src/zlib/adler32.c src/zlib/crc32.c src/zlib/inflate.c \
       src/zlib/inftrees.c src/zlib/inffast.c src/zlib/zutil.c
OBJ = $(SRC:.c=.o) $(ZSRC:.c=.o)
RES = src/app.res

all: carrotav.exe

carrotav.exe: $(OBJ) $(RES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(RES) $(LIBS)

src/zlib/%.o: src/zlib/%.c
	$(CC) -O2 -ffunction-sections -fdata-sections -w -c $< -o $@

%.o: %.c src/av.h
	$(CC) $(CFLAGS) -Isrc/zlib -c $< -o $@

src/app.res: src/app.rc src/resource.h src/app.manifest
	$(WINDRES) -I src --input-format=rc --output-format=coff -i $< -o $@

clean:
	rm -f $(OBJ) $(RES) carrotav.exe

.PHONY: all clean
