# Malcarve - Obfuscated payload extractor for malware samples
# Copyright (C) 2016 Steve Henderson
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

CC32 = gcc -m32 -fPIC
CC64 = gcc -m64 -fPIC
WIN32 = i686-w64-mingw32-gcc -m32
WIN64 = x86_64-w64-mingw32-gcc -m64
CFLAGS = -Wall -Wextra -std=c99 -I include/
MAKEFLAGS = -j8

SRC = $(wildcard src/*.c)
HEADER = $(wildcard include/*.h)

ifdef DEBUG
	CFLAGS += -DDEBUG=1 -O0 -ggdb
else
	CFLAGS += -DDEBUG=0 -O3 -s
endif

all: lib/linux/x86_32/xorpatterns.so lib/linux/x86_64/xorpatterns.so \
	lib/windows/x86_32/xorpatterns.dll lib/windows/x86_64/xorpatterns.dll

lib/linux/x86_32/xorpatterns.so: src/xorpatterns.c $(HEADER) Makefile
	$(CC32) -shared -o $@ $< $(CFLAGS)

lib/linux/x86_64/xorpatterns.so: src/xorpatterns.c $(HEADER) Makefile
	$(CC64) -shared -o $@ $< $(CFLAGS)

lib/windows/x86_32/xorpatterns.dll: src/xorpatterns.c $(HEADER) Makefile
	$(WIN32) -shared -o $@ $< $(CFLAGS)

lib/windows/x86_64/xorpatterns.dll: src/xorpatterns.c $(HEADER) Makefile
	$(WIN64) -shared -o $@ $< $(CFLAGS)

clean:
	rm -f lib/linux/x86_32/*.so lib/linux/x86_64/*.so \
	lib/windows/x86_32/*.dll lib/windows/x86_64/*.dll
