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

from malcarve.schemes import rol, xor


MAX_STRING_LEN = 512


def deob(buf, schemes):
    scanner = StringScanner('url', 12, 256, 8, [])
    scanner.add_scheme(xor.XORPatternFinder('xor', 'xor key patterns', [], [], []))
    scanner.add_scheme(rol.ROLFinder('rol', 'rotate', [], [], []))
    scanner.add_pattern((0, b'http://'))

    for x in scanner.deob(buf):
        yield x


class URLValidator(object):
    # at least 2 domains deep and optionally any valid chars after (including ports).. no checking for user:pass
    pattern = re.compile(rb'((ftp|http)s?://[a-z\-0-9]{1,256}\.[a-z\-0-9]{1,256}([a-z\-0-9\_./:\%\?\#\=\+\~])*)', re.I)
    # PE certificate urls will often run into ascii numbers
    fixers = (
        b".cer0",
        b".com0",
        b".com1",
        b".com/0",
        b".crl0",
        b".crt0",
        b".htm0",
        b".html0",
        b"/ca10",
        b"/CPS0",
        b"/cps0",
        b"/DPM0",
        b"/policy/0",
        b"/repository0",
        b"/rpa0",
        b"/ts0",
        # happens with add encoding list of urls (comma gets translated)
        b"+",
    )

    def __init__(self, checks):
        self.checks = checks

    def validate(self, buf):
        """
        Simple checks on whether this looks like a valid URL or not.
        """
        # strip nulls for wide char, etc.
        #buf = bytes([x for x in buf if x != 0])
        # TODO: split if multiple urls run into each other
        valid = URLValidator.pattern.match(buf)
        if valid:
            url = valid.group(1)
            if url.endswith(URLValidator.fixers):
                return 0, len(url)-1
            if url[:-1].endswith(URLValidator.fixers):
                return 0, len(url)-2
            return 0, len(url)
        return -1, -1


class UAValidator(object):
    pattern = re.compile(rb'(Mozilla/\d([ A-Za-z\-0-9\_./:\%\?\#\=\+\~\(\);,]){2,256})')

    def __init__(self, checks):
        self.checks = checks

    def validate(self, buf):
        """
        Simple checks on whether this looks like a valid URL or not.
        """
        # strip nulls for wide char, etc.
        #buf = bytes([x for x in buf if x != 0])
        valid = UAValidator.pattern.match(buf)
        if valid:
            ua = valid.group(1)
            return 0, len(ua)
        return -1, -1


class NoopValidator(object):
    def __init__(self, checks):
        pass

    def validate(self, buf):
        return 0, len(buf)


class StringScanner(object):
    """
    Scanning class to find embedded/obfuscated strings.
    """
    def __init__(self, name, scan_min, scan_max, min_size, validation, **kwargs):
        self.name = name
        self.scan_min = scan_min
        self.scan_max = scan_max
        self.min_size = min_size
        # a bit of a hack as can get a list
        if not validation:
            self.validator = NoopValidator(validation)
        elif 'url' in validation:
            self.validator = URLValidator(validation)
        elif 'useragent' in validation:
            self.validator = UAValidator(validation)
        else:
            raise Exception('Unknown validation for string')
        self.schemes = []
        self.patterns = []

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
        Deobfuscate any embedded strings.
        
        :param buf: Byte string buffer to scan
        :return: Generator of deobfuscated details (dict)
        """
        for offset, pat in self.patterns:
            for scheme in self.schemes:
                nexti = 0
                while True:
                    match = scheme.locate(buf[nexti:len(buf) - self.min_size], pat, offset,
                                          None, None)
                    if not match:
                        break
                    match['offset'] += nexti
                    nexti = match['offset'] + 1
                    match = scheme.extract(buf, match, min(MAX_STRING_LEN, len(buf)-match['offset']))
                    start, end = self.validator.validate(match['content'])
                    size = end - start
                    if size > 0:
                        match['payload_type'] = self.name
                        match['pattern'] = pat
                        match['content'] = match['content'][start:end]
                        match['length'] = size
                        yield match

