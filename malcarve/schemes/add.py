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

def add(buf, key, encode=True):
    """
    Single byte add/sub.
    Encode to add, decode to sub.
    """
    if type(key) != int:
        key = ord(key)
    if not encode:
        key *= -1
    if type(buf) != bytes:
        buf = buf.encode()
    return bytes(((x + key) % 256 for x in buf))

def findadd(buf, pattern, pattern_offset):
    """
    Simple brute forcer for single byte add obfuscations.
    """
    # should be quicker to modify pattern not buf
    addpats = []
    for i in range(1, 256):
        # assume we'll also be doing xor and skip 0x80 as equivalent
        if i == 0x80:
            continue
        addpats.append(re.escape(add(pattern, i)))
    pat = b'(%s)' % b'|'.join(addpats)
    for x in re.finditer(pat, buf[pattern_offset:]):
        i = addpats.index(re.escape(x.group(0))) + 1
        if i >= 0x80:
            i += 1
        return {'scheme': 'add',
               'key': bytes([i]),
               'keysize': 1,
               'offset': x.start(),
               'modifiers': {},
               }

class AddFinder(object):
    """
    Finds simple, single byte additions in byte streams and deobfuscates their content.
    """
    def __init__(self, name, description, schemes, modifiers, max_keysize, **kwargs):
        self.name = name
        self.description = description
        # TODO.. maybe remove?
        self.enabled_schemes = schemes
        self.enabled_modifiers = modifiers
        self.max_keysize = max_keysize

    def locate(self, buf, pattern, pattern_offset,
               alternate_nulls_offset=None, probable_header=None):
        """
        Attempt to find an obfuscated instance of the pattern in the
        supplied buffer.
        
        :param buf: Byte string buffer to scan
        :param pattern: Plaintext pattern to search for
        :param pattern_offset: Offset of pattern from start of payload/file
        :param alternate_nulls_offset: Alternate location to scan for null pattern
        :param probable_header: Workaround for rolling xors where pattern not at 0
        :return: Dictionary of located pattern or empty if not found
        """
        return findadd(buf, pattern, pattern_offset)

    def extract(self, buf, match, size=None):
        """
        Extract the deobfuscated content of the matched scheme from the buffer.
        
        :param buf: Byt string buffer that was matched
        :param match: Dictionary of match details to extract
        :return: Dictionary of match with deobfsucated content
        """
        if not size:
            end = len(buf)
        else:
            end = match['offset'] + size

        content = add(buf[match['offset']:],
                          match['key'],
                          encode=False)
        match['content'] = content
        match['length'] = len(content)

        return match
