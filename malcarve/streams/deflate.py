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

import re
import zlib

class DeflateDecoder(object):
    """
    Generic decoder for zlib/deflate as used in several file formats.
    Eg. PDF, compressed flash, image formats, gzip.
    For complete decoding will probably want to redo as file format
    specific decoders that can parse their formats accurately.
    
    https://tools.ietf.org/html/rfc1950
    """
    def __init__(self, name):
        self.name = name
        # 0x4889 - 4K Window size common in PDF Deflate Filter
        # 0x7801 - 32K Window Low Compression
        # 0x789C - 32K Window Default Compression
        # 0x78DA - 32K Window Best Compression
        # TODO: this is probably not exhaustive and there aren't really fixed bytes
        self.pattern = re.compile(
            rb'((\x48\x89)|(\x78\x01)|(\x78\x9c)|(\x78\xda)|(\xec\xfd)|(\xed\x7c)' +
            rb'|(\xe4\x5c)|(\x7c\x92)|(\x9c\x53)|(\x8c\x8f)|(\xec\x9d)|(\xec\x59)' +
            rb'|(\xc4\x54)|(\xc4\x53)|(\x84\xd0)|(\x9d\x54)|(\xcc\x58)|(\xac\x95)' +
            rb'|(\x8c\x92)|(\xc4\x96))'
        )
        self.min_size = 12

    def decode(self, buf, encoding=None):
        # don't enumerate() as we only want to count successful deflate streams
        # likely lots of false positives with 2 byte pattern.. should tighten up
        i = 0
        for x in re.finditer(self.pattern, buf):
            try:
                # try with zlib header, 0 = auto detect wbits
                yield {'encoding': 'deflate',
                       'stream_id': i,
                       'offset': x.start(),
                       'stream': zlib.decompress(buf[x.start():], 0),
                       }
                i += 1
            except Exception:
                # try without zlib header 'raw'
                try:
                    yield {'encoding': 'deflate',
                           'stream_id': i,
                           'offset': x.start(),
                           'stream': zlib.decompress(buf[x.start():], -15),
                           }
                    i += 1
                except Exception:
                    # give up
                    pass
    def validate(self, buf):
        if len(buf) < self.min_size:
            raise Exception("Too Small")
        return buf
