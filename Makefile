# CarrotAV - build with mingw-w64 (i686) or MinGW on Windows
CC      = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres
CFLAGS  = -O2 -municode -mwindows -Wall -Wextra -Wno-unused-parameter \
          -fno-ident -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--gc-sections -s -static-libgcc
LIBS    = -loleaut32 -luuid -lcomctl32 -lshlwapi -lshell32 -lole32 -ladvapi32 -lcomdlg32 -lgdi32 \
          -luser32 -lkernel32 -lm

SRC = src/main.c src/scan.c src/sigdb.c src/protect.c src/fw.c src/realtime.c src/baseline.c src/archive.c
OBJ = $(SRC:.c=.o)
RES = src/app.res

all: carrotav.exe

carrotav.exe: $(OBJ) $(RES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(RES) $(LIBS)

%.o: %.c src/av.h
	$(CC) $(CFLAGS) -c $< -o $@

src/app.res: src/app.rc src/resource.h src/app.manifest
	$(WINDRES) -I src --input-format=rc --output-format=coff -i $< -o $@

clean:
	rm -f $(OBJ) $(RES) carrotav.exe

.PHONY: all clean
