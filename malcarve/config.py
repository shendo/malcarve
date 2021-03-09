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

import binascii
from collections import namedtuple
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser
import os
from pkg_resources import DistributionNotFound, Requirement, ResourceManager

# path to conf files if package not installed
SOURCE_PATH = os.path.join(os.path.dirname(__file__), 'conf')
SYSTEM_PATH = "/etc/malcarve"
USER_PATH = os.path.expanduser('~/.malcarve')


def installed_location(filename):
    """
    Returns the full path for the given installed file or None if not found.
    """
    try:
        return ResourceManager().resource_filename(Requirement.parse("malcarve"), filename)
    except DistributionNotFound:
        return None

def value_list(value):
    """
    Given a comma-separated string value return a corresponding
    list of strings.
    """
    return [x.strip() for x in value.split(',')]

def value_to_int(value):
    """
    Given a string value, that may be hex encoded (start with 0x), converts
    to an integer.
    """
    if value.startswith('0x'):
        return int(value[2:], 16)
    return int(value)

def value_to_bytes(value):
    """
    Given a string value, that may be hex encoded (start with 0x), converts
    to a string byte list.
    """
    if value.startswith('0x'):
        return binascii.unhexlify(value[2:])
    return bytes(value)

def value_to_bool(value):
    """
    Given a string value will convert to a boolean.
    """
    if value.lower() in ('true', 'yes', 'on'):
        return True
    return False


class Config:
    """
    Main config file parser for malcarve.
    """
    def __init__(self, cfg='malcarve.conf'):
        installed_path = installed_location(cfg) or 'notfound'
        parser = ConfigParser()
        parser.read([os.path.join(USER_PATH),
                     os.path.join(SYSTEM_PATH),
                     installed_path,
                     os.path.join(SOURCE_PATH, cfg)])

        self.payloads = {}
        self.deobfuscators = {}
        self.decoders = {}
        self.embedded_only = value_to_bool(parser.get('malcarve', 'embedded_only'))
        self.max_stream_depth = value_to_int(parser.get('malcarve', 'max_stream_depth'))

        for x in value_list(parser.get('malcarve', 'payloads')):
            if not x:
                continue
            payload = namedtuple('payload', 'name module description deobs scan_min scan_max min_size patterns validation other')
            payload.name = x
            payload.description = parser.get(x, 'description')
            payload.class_name = parser.get(x, 'module')
            payload.deobs = value_list(parser.get(x, 'deobfuscators'))
            payload.scan_min = int(parser.get(x, 'scan_min'))
            payload.scan_max = int(parser.get(x, 'scan_max'))
            payload.min_size = int(parser.get(x, 'min_size'))
            payload.validation = value_list(parser.get(x, 'validation'))
            payload.patterns = []
            for name, value in parser.items(x):
                if not name.startswith('pattern.'):
                    continue
                if not value.strip():
                    continue
                vals = value_list(value)
                if len(vals) != 2:
                    raise('ConfigError: invalid value %s %s ' % (name, value))
                payload.patterns.append((value_to_int(vals[0]), value_to_bytes(vals[1])))
            payload.other = {}
            self.payloads[payload.name] = payload

        for x in value_list(parser.get('malcarve', 'deobfuscators')):
            if not x:
                continue
            deob = namedtuple('deob', 'name module schemes description max_keysize modifiers other')
            deob.name = x
            deob.class_name = parser.get(x, 'module')
            deob.description = parser.get(x, 'description')
            deob.schemes = value_list(parser.get(x, 'schemes'))
            deob.max_keysize = value_to_int(parser.get(x, 'max_keysize'))
            deob.modifiers = value_list(parser.get(x, 'modifiers'))
            deob.other = {}
            self.deobfuscators[deob.name] = deob

        for x in value_list(parser.get('malcarve', 'streams')):
            if not x:
                continue
            decoder = namedtuple('decoder', 'name module')
            decoder.name = x
            decoder.class_name = parser.get(x, 'module')
            self.decoders[decoder.name] = decoder
