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

class PDFValidator(object):
    def __init__(self, checks):
        self.checks = checks

    def validate(self, buf):
        """
        Simple checks on whether this looks like a valid PDF file or not.
        """
        if 'pdf_version' in self.checks:
            try:
                f = float(buf[5:8])
                if f < 1.0 or f > 1.7:
                    return -1, -1
            except:
                return -1, -1

        eof_marker = b'%%EOF\r\n'
        end = buf.find(eof_marker)
        if end < 0:
            eof_marker = b'%%EOF\n'
            end = buf.find(eof_marker)
            if end < 0:
                eof_marker = b'%%EOF'
                end = buf.find(eof_marker)
                if end < 1:
                    # give up
                    return -1, -1
        eof = end + len(eof_marker)
        return 0, eof

class PDFScanner(object):
    def __init__(self, name, scan_min, scan_max, min_size, validation, **kwargs):
        self.name = name
        self.scan_min = scan_min
        self.scan_max = scan_max
        self.min_size = min_size
        self.validator = PDFValidator(validation)
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
