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

import os
import platform
import sys

from ctypes import byref, cdll, create_string_buffer
from ctypes import c_bool, c_size_t, c_int32, pointer

import malcarve

def load_library(library_name):
    """
    Load the ibrary with the given name using ctypes.
    Code lifted from https://github.com/sptonkin/fuzzyhashlib
    """
    # Figure out architecture.
    if platform.architecture()[0].startswith("64"):
        arch = "x86_64"
    else:
        arch = "x86_32"

    # Figure out OS info.
    if sys.platform.startswith("linux"):
        os_platform = "linux"
        extension = "so"
    elif sys.platform.startswith("darwin"):
        os_platform = "darwin"
        extension = "dylib"
    elif sys.platform.startswith("win"):
        os_platform = "windows"
        extension = "dll"
    else:
        raise Exception("Unsupported platform - %s" % sys.platform)

    library_filename = "%s.%s" % (library_name, extension)
    library_path = os.path.join(os.path.dirname(malcarve.__file__),
                                "ext",
                                "lib",
                                os_platform,
                                arch,
                                library_filename)
    return cdll.LoadLibrary(library_path)

x = load_library('xorpatterns')

def xor(buf, key, key_step=0, offset=0,
        null_preserve=False, rolling=False, decode=False):
    """
    XOR the buffer with the supplied key.
    
    :param buf: Byte string to obfscuated/deobfuscate.
    :param key: Key string to use for XOR.
    :param key_step: Integer to modify the key by after each XOR.
    :param offset: Offset from start of file to this buffer.
    :param null_preserve: Ignore Null and XOR values.
    :param rolling: Rolling XOR where previous output is next key
    :param decode: Are we encoding or decoding (only affects some modifiers)
    :return: XOR'ed buffer
    """
    outbuf = create_string_buffer(len(buf))
    if key_step:
        x.xor_countup(buf, c_size_t(len(buf)),
                      key, c_size_t(len(key)),
                      key_step, c_size_t(offset), c_bool(null_preserve),
                      outbuf)
    elif rolling:
        x.xor_rolling(buf, c_size_t(len(buf)),
                      key, c_size_t(len(key)),
                      decode, outbuf)
    else:
        x.xor(buf, c_size_t(len(buf)),
              key, c_size_t(len(key)),
              c_bool(null_preserve),
              outbuf)
    return outbuf.raw

def keypattern(pattern, original):
    """
    Given a buffer XOR'ed with a plaintext pattern, attempt
    to identify a repeating XOR key pattern.
    
    :param pattern: The XOR'ed buffer
    :param original: Original plaintext used
    :return: Dict with details of pattern or empty if none identified 
    """
    keybuf = create_string_buffer(64)
    keysize = c_size_t()
    np = c_bool()
    step = c_int32()
    found = x.keypattern(pattern,
                         original, 0, c_size_t(min(8, int(len(pattern)/4))),
                         keybuf, pointer(keysize),
                         pointer(np), pointer(step))
    if found:
        res = {
            'scheme': 'xor',
            'key': keybuf.raw[:keysize.value],
            'keysize': keysize.value,
        }
        modifiers = {}
        if np:
            modifiers['null_preserve'] = True
        if step:
            modifiers['step'] = step.value
        res['modifiers'] = modifiers
        return res
    return {}

def findxor(buf, pattern, patoffset, nulloffset=None, header=None):
    """
    Attempt to identify a XOR'ed pattern in the supplied buffer.
    
    :param buf: Byte string to scan
    :param pattern: Byte string pattern to search for
    :param patoffset: Integer offset where pattern expected relative to start
    :param nulloffset: Alternative location to test for null bytes
    :param header: Header pattern hint if not searching at offset 0
    :return: Dict with details of located scheme or empty if none found
    """
    keybuf = create_string_buffer(64)
    keysize = c_size_t()
    np = c_bool()
    step = c_int32()
    roll = c_bool()
    offset = c_size_t()

    found = x.findxor(buf, c_size_t(len(buf)),
                      pattern, c_size_t(len(pattern)), c_size_t(patoffset),
                      pointer(offset), keybuf, pointer(keysize),
                      pointer(np), pointer(step), pointer(roll))
    if found:
        res = {
            'offset': offset.value,
            'scheme': 'xor',
            'key': keybuf.raw[:keysize.value],
            'keysize': keysize.value,
        }
        modifiers = {}
        if np:
            modifiers['null_preserve'] = True
        if step:
            modifiers['step'] = step.value
        if roll:
            modifiers['rolling'] = True

        res['modifiers'] = modifiers
        # TODO: move into c code?
        # we can miss null preservation if not long enough runs in pattern
        if nulloffset and not np:
            check_location = offset.value + nulloffset
            if buf[check_location:check_location + keysize.value] == b'\x00' * keysize.value:
                modifiers['null_preserve'] = True
        # rolling start key value likely incorrect if not at offset 0 :(
        # try to fix with expected/known header bytes
        if roll and patoffset and header and len(header) >= keysize.value:
            res['key'] = bytes([c ^ buf[offset.value + i]
                                  for i, c in enumerate(header) if i < keysize.value])
        return res
    return {}


class XORPatternFinder(object):
    """
    Finds XOR patterns in byte streams and deobfuscates their content.
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
        return findxor(buf, pattern, pattern_offset, alternate_nulls_offset, probable_header)

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
        content = xor(buf[match['offset']:end],
                          match['key'],
                          null_preserve=match['modifiers'].get('null_preserve'),
                          key_step=match['modifiers'].get('step', 0),
                          rolling=match['modifiers'].get('rolling'),
                          decode=True)
        match['content'] = content
        match['length'] = len(content)

        # plaintext special case
        if match['scheme'] == 'xor' and match['key'] == b'\x00' \
            and (not match['modifiers'] \
                 or match['modifiers'] == {'null_preserve': True}):
            match['scheme'] = 'plain'
            match['key'] = None
            match['keysize'] = 0
            match['modifiers'] = {}
        return match
