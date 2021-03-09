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

from malcarve.schemes import rol

def test_rol():
    assert rol.rol(b'\x00\x01\x02\x03', b'\x01') == b'\x00\x02\x04\x06'
    assert rol.rol(b'\x00\x02\x04\x06', b'\x07') == b'\x00\x01\x02\x03'
    # decode does the equiv of ror
    assert rol.rol(b'\x00\x02\x04\x06', b'\x01', encode=False) == b'\x00\x01\x02\x03'
    assert rol.rol(b'\x0f\x1a\xff\xcc', b'\x02') == b'\x3c\x68\xff\x33'
    assert rol.rol(b'\x0f\x1a\xff\xcc', b'\x08') == b'\x0f\x1a\xff\xcc'


def test_findrol():
    assert rol.findrol(b'\x00\x02\x04\x06', b'\x00\x01\x02\x03', 0) == \
        {'offset': 0, 'scheme': 'rol', 'key': b'\x01', 'keysize': 1, 'modifiers': {}}
    assert rol.findrol(b'asdfr221\x00\x02\x04\x06', b'\x00\x01\x02\x03', 0) == \
        {'offset': 8, 'scheme': 'rol', 'key': b'\x01', 'keysize': 1, 'modifiers': {}}
