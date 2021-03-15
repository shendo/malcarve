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

from base64 import b64decode
from binascii import unhexlify
import re


class ChrDecoder(object):
    """
    A stream decoder that will attempt to find and decode
    runs of character code conversions like:
    - Chr(111),Chr(73)
    - 123,45,67
    """
    def __init__(self, name):
        self.name = name
        self.pattern = re.compile(rb'(Chr\()?\d{1,3}\)?(\s*[\s\-\,\&\|O\%\^\.\;]\s*(Chr\()?\d{1,3}\)?){9,}')
        self.extract = re.compile(rb'(\d{1,3})')
    
    def decode(self, buf, encoding=None):
        for i, x in enumerate(re.finditer(self.pattern, buf)):
            try:
                buf = bytes((int(c.group(1)) for c in re.finditer(self.extract, x.group(0))))
            except Exception as ex:
                continue
            yield {'encoding': 'charcodes',
                   'stream_id': i,
                   'offset': x.start(),
                   'stream': buf,
                   }


class HexDecoder(object):
    """
    A stream decoder that will attempt to extract and unhexlify
    any base16 streams present in scanned buffers.
    """
    def __init__(self, name):
        self.name = name
        # allow separator char like space, comma, %
        self.pattern = re.compile(rb'([a-f0-9]{1,}[\,\^\%]?\s*){10,}|([A-F0-9]{2,}[\,\^\%]?\s*){10,}')

    def decode(self, buf, encoding=None):
        i = 0
        joined = b''
        first_offset = 0
        last_offset = 0
        for x in re.finditer(self.pattern, buf):
            try:
                m = x.group(0).lower() \
                    .replace(b',', b'') \
                    .replace(b'%', b'') \
                    .replace(b'^', b'')
                m = re.sub(rb'\s+', b'', m)
                if not joined or x.start() - last_offset <= 50:
                    joined += m
                else:
                    joined = m
                    first_offset = x.start()
                if not i:
                    first_offset = x.start()
                last_offset = x.end()
                i += 1

                if len(m) % 2:
                    m = m[:-1]
                s = unhexlify(m)
                yield {'encoding': 'base16',
                       'stream_id': i,
                       'offset': x.start(),
                       'stream': s,
                       }
            except Exception as ex:
                pass
        # try joining the found blobs?
        if i <= 1:
            return
        try:
            joined = unhexlify(joined)
            yield {'encoding': 'base16',
                   'stream_id': 0,
                   'offset': first_offset,
                   'stream': joined,
                   }
        except Exception:
            pass


class B64Decoder(object):
    """
    A stream decoder that will attempt to identify and
    extract any base64 encoded data contained in scanned buffers.
    """

    UPPER = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(self, name):
        self.name = name
        self.pattern = re.compile(rb'([a-zA-Z0-9+/=]{20,}\s*)+')

    def decode(self, buf, encoding=None):
        i = 0
        joined = b''
        first_offset = 0
        for x in re.finditer(self.pattern, buf):
            # trying to filter out straight hex encoded
            # all our patterns should result in mix of casing
            if not any(c in B64Decoder.UPPER for c in x.group(0)[:100]):
                continue
            try:
                chunk = re.sub(rb'\s+', b'', x.group(0))
                rem = len(chunk) % 4
                if rem == 3:
                    chunk += b'='
                elif rem == 2:
                    chunk += b'=='
                elif rem == 1:
                    # extra char (or multiple missing) somewhere
                    chunk = chunk[:-1]
                s = b64decode(chunk)
                if not joined.endswith(b'='):
                    joined += re.sub(rb'\s+', b'', x.group(0))
                    i += 1
                    first_offset = x.start()

                yield {'encoding': 'base64',
                       'stream_id': i,
                       'offset': x.start(),
                       'stream': s,
                       }
            except Exception as ex:
                pass

        # try joining the found blobs?
        if i <= 1:
            return
        try:
            joined = base64.decode(joined)
            #yield {'encoding': 'base64',
            #       'stream_id': 0,
            #       'offset': first_offset,
            #       'stream': joined,
            #       }
        except:
            pass

class VariableDecoder(object):
    """
    A stream decoder that will attempt to identify and
    extract string variable definition/concatenations in scripts.
    """
    def __init__(self, name):
        self.name = name
        self.varpattern = re.compile(rb'([a-zA-Z0-9\s+&=_\[\(\]\)]{2,30}(\"|\')([a-zA-Z0-9+/=]{16,})(\"|\')\s+\;?){2,}')
        self.stringpattern = re.compile(rb'(\'|\")([a-zA-Z0-9+/=]+)(\'|\")')

    def decode(self, buf, encoding=None):
        for i, x in enumerate(self.varpattern.finditer(buf, re.DOTALL)):
            b = b''.join(z[1] for z in self.stringpattern.findall(x.group(0)))
            # ughh.. did we just combine multi b64 strings?  they won't decode together if padded
            while b:
                eql = b.find(b'=')
                if eql >= 0:
                    if len(b) > eql+1 and b[eql+1] == 61:
                        eql += 1
                    yield {'encoding': 'vars',
                           'stream_id': i,
                           'offset': x.start(),
                           'stream': b[:eql+1],
                           }
                    b = b[eql+1:]
                    continue
                yield {'encoding': 'vars',
                       'stream_id': i,
                       'offset': x.start(),
                       'stream': b,
                       }
                break
