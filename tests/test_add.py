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

from malcarve.schemes import add

def test_add():
    assert add.add(b'\x00\x01\x02\x03', b'\x01') == b'\x01\x02\x03\x04'
    assert add.add(b'\xff\x02\xfe\x06', b'\x07') == b'\x06\x09\x05\x0d'
    # decode does the equiv of sub
    assert add.add(b'\x01\x02\x03\x04', b'\x01', encode=False) == b'\x00\x01\x02\x03'
    assert add.add(b'\x0f\x1a\xff\xcc', b'\xff') == b'\x0e\x19\xfe\xcb'


def test_findadd():
    assert add.findadd(b'\x01\x02\x03\x04', b'\x00\x01\x02\x03', 0) == \
        {'offset': 0, 'scheme': 'add', 'key': b'\x01', 'keysize': 1, 'modifiers': {}}
    assert add.findadd(b'asdfr221\x01\x02\x03\x04', b'\x00\x01\x02\x03', 0) == \
        {'offset': 8, 'scheme': 'add', 'key': b'\x01', 'keysize': 1, 'modifiers': {}}

