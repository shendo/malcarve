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

from __future__ import absolute_import
from __future__ import unicode_literals

import io
import struct
import zipfile
import zlib


class ZipValidator(object):
    def __init__(self, checks):
        self.checks = checks

    def validate(self, buf):
        """
        Simple checks on whether this looks like a valid Zip file or not.
        """
        # ensure startsmwith magic
        if buf[:2] != b'PK':
            return -1, -1
        try:
            zipfile.ZipFile(io.BytesIO(buf))
        except Exception as ex:
            return -1, -1

        end = -1
        # go forwards instead of backwards in case of multiple embedded zips.. slower
        for i in range(len(buf)):
            if i > len(buf) -22:
                break
            if buf[i:i+8] == b'\x50\x4b\x05\x06\x00\x00\x00\x00': # EOCD and not multidisk
                # found end-of-central-directory
                end = i+22
                break
            # TODO: handle comments field?
        return 0, end
        

class ZipScanner(object):
    def __init__(self, name, scan_min, scan_max, min_size, validation, **kwargs):
        self.name = name
        self.scan_min = scan_min
        self.scan_max = scan_max
        self.min_size = min_size
        self.validator = ZipValidator(validation)
        self.schemes = []
        self.patterns = []
        self.nulls_offset = None

    def add_scheme(self, scheme):
        self.schemes.append(scheme)

    def add_pattern(self, pattern):
        self.patterns.append(pattern)

    def deob(self, buf):
        for offset, pat in self.patterns:
            for scheme in self.schemes:
                nexti = 0
                while True:
                    match = scheme.locate(buf[nexti:len(buf) - self.min_size], pat, offset, self.nulls_offset)
                    if not match:
                        break
                    match['offset'] += nexti
                    nexti = match['offset'] + 1
                    match = scheme.extract(buf, match)
                    start, end = self.validator.validate(match['content'])
                    size = end - start
                    if size > 0:
                        match['payload_type'] = self.name
                        match['pattern'] = pat
                        if size < match['length']:
                            match['content'] = match['content'][:size]
                            match['length'] = size
                        nexti += size - 1
                        yield match

