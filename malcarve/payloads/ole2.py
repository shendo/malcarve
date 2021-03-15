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

import olefile


class OLEValidator(object):
    """
    A class to validate OLE2/Compound Document files.

    Uses olefile to parse content.
    """
    def __init__(self, checks):
        self.checks = checks

    def validate(self, buf):
        """
        Parse and determine end of ole compound file.
        """
        if not buf.startswith(b'\xd0\xcf\x11\xe0'):
            return -1, -1
        try:
            ole = olefile.OleFileIO(buf)
            eof = ole.nb_sect * ole.sector_size
            # sometimes seems to include/exclude header
            eof += 512
        except Exception:
            return -1, -1

        return 0, min(eof, len(buf))

class OLEScanner(object):
    """
    Scan buffer for ole2 compound files under configured schemes.
    """
    def __init__(self, name, scan_min, scan_max, min_size, validation, **kwargs):
        self.name = name
        self.scan_min = scan_min
        self.scan_max = scan_max
        self.min_size = min_size
        self.validator = OLEValidator(validation)
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
                            match['content'] = match['content'][start:end]
                            match['length'] = size
                        yield match
