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

from malcarve.schemes import rol, xor

import struct

import lznt1


dos_header = b'MZ'
dos_to_pe_offset = 0x3c
pe_header = b'PE\x00\x00'
pe_header_size = 0x18
pe_section_count = 0x6
pe_opt_hdr_size = 0x14
section_name = 0x00
section_raw_size = 0x10
section_raw_addr = 0x14

pe_offset_min = 0x30
pe_offset_max = 0x200

common_sections = [
    b'.text',
    b'.UPX0',
    b'.data',
    b'.rdata',
    b'.rsrc',
    b'.reloc',
    b'.bss',
    ]


def deob(buf, schemes):
    scanner = PEScanner('pe_file', 10000, 2048000, 10000, ['pe_header', 'pe_size'])
    scanner.add_scheme(xor.XORPatternFinder('xor', 'xor key patterns', [], [], []))
    scanner.add_scheme(rol.ROLFinder('rol', 'rotate', [], [], []))
    # note: whole pattern does not need to match, just enough to detect a key sequence
    # this is considered a feature not a bug :)
    # it allows matching where part of the dos stub has been tampered/nopped (if first few bytes remain)
    # though does mean we need to perform validation as will get more false positives for small keys
    scanner.add_pattern((0x40, b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot'))
    scanner.add_pattern((0x40, b'\xba\x10\x00\x0e\x1f\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x90\x90This program must'))
    # try finding PE incase dos stub tampered/zeroed.. need to find start of MZ in that case
    #scanner.add_pattern((0x100, b'PE\x00\x00\x4c\x01')) # i386
    #scanner.add_pattern((0x100, b'PE\x00\x00\x64\x86')) # x64


    for x in scanner.deob(buf):
        yield x


class PEValidator(object):
    def __init__(self, checks):
        self.checks = checks

    def validate(self, buf):
        """
        Simple checks on whether this looks like a valid PE file or not.
        """
        sof = 0
        eof = len(buf)
        pe_offset = 0
        section_offset = 0
        section_count = 0
        try:
            pe_offset = struct.unpack('<I', buf[dos_to_pe_offset:dos_to_pe_offset + 4])[0]
            section_count = struct.unpack('<H', buf[pe_offset + pe_section_count:pe_offset + pe_section_count + 2])[0]
            opt_header_size = struct.unpack('<H', buf[pe_offset + pe_opt_hdr_size:pe_offset + pe_opt_hdr_size + 2])[0]
            section_offset = pe_offset + pe_header_size + opt_header_size
            end_sections = 0
            for i in range(section_count):
                off = section_offset + i * 40
                section_size = struct.unpack('<I', buf[off + section_raw_size:off + section_raw_size + 4])[0]
                section_start = struct.unpack('<I', buf[off + section_raw_addr:off + section_raw_addr + 4])[0]
                end_sections = max(end_sections, section_start + section_size)
                if end_sections > 2 * eof:
                    raise Exception("Improbable/corrupt sections. Skipping.")
            eof = end_sections
        except Exception:
            return -1, -1

        # could check attributes of header values too, versions, etc.
        # note: common for malware to have tampered with headers/magic to avoid detection
        if not buf[:2] == dos_header:
            if 'dos_header' in self.checks:
                return -1, -1
            else:
                # TODO: some way to feedback header fix ups to user
                # TODO: replace fully zeroed out dos/pe headers
                # just replace first few bytes all exe/dll really needs
                # is MZ magic and PE offset in DOS header
                buf = b'MZ\x90\x00\x03\x00\x00\x00' + buf[8:]
                # TODO this won't work, bytes is immutable

        if pe_offset < pe_offset_min or pe_offset > pe_offset_max or not \
            buf[pe_offset:pe_offset + 4] == pe_header:
            if 'pe_header' in self.checks:
                return -1, -1
            else:
                # TODO: some way to feedback header fix ups
                buf = b''.join((buf[:pe_offset], b'PE\0\0' , buf[pe_offset+4:]))

        if 'sections' in self.checks:
            section_table = buf[section_offset:section_offset + section_count * 40]
            if not any([x in section_table for x in common_sections]):
                return -1, -1

        if 'pe_size' in self.checks:
            if eof < 100 or eof > len(buf):
                # some wiggle room, maybe because lack of padding?
                if eof > len(buf) and len(buf) - eof < 20:
                    return sof, eof
                return -1, -1

        return sof, eof


class PEScanner(object):
    """
    Scanning class to find embedded Windows PE files.
    """
    def __init__(self, name, scan_min, scan_max, min_size, validation, **kwargs):
        self.name = name
        self.scan_min = scan_min
        self.scan_max = scan_max
        self.min_size = min_size
        self.validator = PEValidator(validation)
        self.schemes = []
        self.patterns = []
        self.nulls_offset = kwargs.get('nulls_offset', 0x28)
        #self.nulls_offset = kwargs.get('nulls_offset', 0x04)
        # for some xor schemes we really need to know what the first
        # byte/s expected are, even if we are using a pattern at a diff
        # offset... is there better way to do this for rolling xors?
        # it only needs 'keysize' bytes to calculate starting key
        # despite being able to identify the scheme at any later point
        self.possible_header = b'MZ\x90\x00\x03\x00\x00\x00\x04'

    def add_scheme(self, scheme):
        """
        Add obfuscation scheme to search for.
        
        :param scheme: Scheme scanning object
        """
        self.schemes.append(scheme)

    def add_pattern(self, pattern):
        """
        Add plaintext pattern to search for.
        
        :param pattern: Tuple of offset, string pattern
        """
        self.patterns.append(pattern)

    def deob(self, buf):
        """
        Deobfuscate any embedded PE files from supplied buffer.
        
        :param buf: Byte string buffer to scan
        :return: Generator of deobfuscated details (dict)
        """
        for offset, pat in self.patterns:
            for scheme in self.schemes:
                nexti = 0
                while True:
                    match = scheme.locate(buf[nexti:len(buf) - self.min_size], pat, offset,
                                          self.nulls_offset, self.possible_header)
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
                        # identified earlier end of pe file?
                        # include both as overlay can be used as storage area
                        if size < match['length']:
                            match['content_with_overlay'] = match['content'][start:]
                            match['length_with_overlay'] = match['length'] - start
                            match['content'] = match['content'][start:end]
                            match['length'] = size
                        yield match


class LZNT1PEScanner(PEScanner):
    """
    Variation of Windows PE scanner that can find LZNT1 compressed payloads.
    """
    def deob(self, buf):
        for offset, pat in self.patterns:
            for scheme in self.schemes:
                nexti = 0
                while True:
                    match = scheme.locate(buf[nexti:len(buf) - self.min_size], pat, offset,
                                          self.nulls_offset, self.possible_header)
                    if not match:
                        break
                    match['offset'] += nexti
                    nexti = match['offset'] + 1
                    match = scheme.extract(buf, match)
                    try:
                        match['content'] = lznt1.decompress(match['content'])
                    except Exception:
                        continue
                    match['scheme'] = 'lznt1.' + match['scheme']
                    start, end = self.validator.validate(match['content'])
                    size = end - start
                    if size > 0:
                        match['payload_type'] = self.name
                        match['pattern'] = pat
                        # identified earlier end of pe file?
                        # include both as overlay can be used as storage area
                        if size < match['length']:
                            match['content_with_overlay'] = match['content'][start:]
                            match['length_with_overlay'] = match['length'] - start
                            match['content'] = match['content'][start:end]
                            match['length'] = size
                        yield match
