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

from malcarve.schemes import xor

def test_xor():
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01') == b'\x02\x00\x03\x01'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', null_preserve=True) == b'\x02\x01\x03\x00'
    assert xor.xor(b'\x00\x00\x00\x00', b'\x01', null_preserve=True) == b'\x00\x00\x00\x00'
    assert xor.xor(b'\x00\x01\x00\x01', b'\x01', null_preserve=True) == b'\x00\x01\x00\x01'
    assert xor.xor(b'\x00\x01\x00\x01', b'\x02', null_preserve=True) == b'\x00\x03\x00\x03'
    # round trip
    assert xor.xor(xor.xor(b'\x00\x01\x00\x01',
                    b'\x02', null_preserve=True),
                    b'\x02', null_preserve=True) == b'\x00\x01\x00\x01'

def test_xor_multibyte():
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01\x02') == b'\x02\x03\x03\x02'
    assert xor.xor(b'\x03\x01\x02\x00\x00\x00', b'\x01\x02', null_preserve=True) == b'\x02\x03\x03\x02\x00\x00'
    assert xor.xor(b'\x01\x02\x00\x03\x00\x00', b'\x01\x02', null_preserve=True) == b'\x01\x02\x01\x01\x00\x00'
    assert xor.xor(b'\x03\x01\x02\x00\x00\x00\x00\x00', b'\x01\x02\x03\x04') == b'\x02\x03\x01\x04\x01\x02\x03\x04'
    assert xor.xor(b'\x03\x01\x02\x00\x00\x00\x00\x00', b'\x01\x02\x03\x04', null_preserve=True) == b'\x02\x03\x01\x04\x00\x00\x00\x00'
    # round trip
    assert xor.xor(xor.xor(b'\x03\x01\x02\x00\x00\x00\x00\x00',
                    b'\x01\x02\x03\x04'),
                    b'\x01\x02\x03\x04') == b'\x03\x01\x02\x00\x00\x00\x00\x00'

def test_xor_with_steps():
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=1) == b'\x02\x03\x01\x04'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=1, offset=1) == b'\x01\x02\x06\x05'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=1, offset=-2) == b'\xfc\x01\x03\x02'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=1, null_preserve=True) == b'\x02\x03\x01\x00'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=3, offset=2) == b'\x04\x0b\x0f\x10'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=-1) == b'\x02\x01\xfd\xfe'
    assert xor.xor(b'\x03\x01\x02\x00', b'\x01', key_step=-1, null_preserve=True) == b'\x02\x01\xfd\x00'
    assert xor.xor(b'\x03\x01\x02\x00\x00\x00', b'\x00\x00', key_step=1) == b'\x03\x01\x03\x00\x02\x00'
    assert xor.xor(b'\x03\x01\x02\x00\x00\x00', b'\xff\xff\x00', key_step=1) == b'\xfc\xfe\x02\x00\x00\x01'
    # round trip
    assert xor.xor(xor.xor(b'\x03\x01\x02\x00',
                    b'\x01', key_step=-1),
                    b'\x01', key_step=-1) == b'\x03\x01\x02\x00'

def test_xor_rolling():
    assert xor.xor(b'\x31\xc2\x50\x69', b'\x90', rolling=True) == b'\xa1\x63\x33\x5a'
    assert xor.xor(b'\x31\xc0\x50\x68', b'\x90\x05', rolling=True) == b'\xa1\xc5\xf1\xad'
    assert xor.xor(b'\x31\xc0\x50\x68\x77\x85', b'\x90\x15\x01\xde', rolling=True) == b'\xa1\xd5\x51\xb6\xd6\x50'
    # round trip
    assert xor.xor(xor.xor(b'\x31\xc0\x50\x68',
                    b'\x90\x05', rolling=True),
                    b'\x90\x05', rolling=True, decode=True) == b'\x31\xc0\x50\x68'

def test_xor_keypattern():
    # not meant to be exposed/used externally but useful for debugging
    assert not xor.keypattern(b'\x19\x07\xfc\x11', b'sdjadkjahdjhsahjsdkahsdkajshdajsdajkhdhjdasasjdh')
    assert xor.keypattern(b'\x19' * 32, b'sdjadkjahdjhsahjsdkahsdkajshdajsdajkhdhjdasasjdh') == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x19', 'modifiers': {}}
    assert xor.keypattern(b'\x19\x07' * 17, b'sdjadkjahdjhsahjsdkahsdkajshdajsdajkhdhjdasasjdh') == \
        {'scheme': 'xor', 'keysize': 2, 'key': b'\x19\x07', 'modifiers': {}}
    assert xor.keypattern(b'\x19\x07\xfc' * 5, b'sdjadkjahdjhsahjsdkahsdkajshdajsdajkhdhjdasasjdh') == \
        {'scheme': 'xor', 'keysize': 3, 'key': b'\x19\x07\xfc', 'modifiers': {}}
    assert xor.keypattern(b'\x19\x07\xfc\x19\x07\xfc\x00\x00\x00\x19\x07\xfc', b'asdewq\x00\x00\x00\x19\x97\xfcadkjahdjhskhdhjdasasjdh') == \
        {'scheme': 'xor', 'keysize': 3, 'key': b'\x19\x07\xfc', 'modifiers': {'null_preserve': True}}
    assert xor.keypattern(b'\x19\x07\xfc\x11\x99\x08\x08\x08' * 5, b'sdjadkjahdjhsahjsdkahsdkajshdajsdajkhdhjdasasjdh') == \
        {'scheme': 'xor', 'keysize': 8, 'key': b'\x19\x07\xfc\x11\x99\x08\x08\x08', 'modifiers': {}}
    assert xor.keypattern(b'\x19\x00\x19\x19\x19\x19', b'a\x00halsaskjdhakdjhad') == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x19', 'modifiers': {'null_preserve': True}}
    # TODO: issue with null preserve and pattern starting with key
    #assert xor.keypattern('\x00\x00\x19\x19\x19', '\x19\x00\x00\xab\xcd\x3f') == \
    #    {'scheme': 'xor', 'keysize': 1, 'key': '\x19', 'modifiers': {'null_preserve': True}}
    assert xor.keypattern(b'\xc0\xbf\xbe\xbd\xbc\xbb\xba\xb9\xb8\xb7', '\xef\xa1\xcd\x01\x01\x01') == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\xc0', 'modifiers': {'step':-1}}

# Note: need minimum 6 byte match/pattern now...
def test_findxor():
    assert xor.findxor(b'\x02\x00\x03\x01\x01\x01', b'\x03\x01\x02\x00\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {}, 'offset': 0}
    assert xor.findxor(b'\x02\x00\x03\x00\x00\x00', b'\x03\x01\x02\x00\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {'null_preserve': True}, 'offset': 0}
    assert xor.findxor(b'\x02\x03\x03\x02\x00\x00\x02\x03\x03\x02\x00\x00', b'\x03\x01\x02\x00\x00\x00\x03\x01\x02\x00\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 2, 'key': b'\x01\x02', 'modifiers': {'null_preserve': True}, 'offset': 0}
    assert xor.findxor(b'hqwerqrdfbweqrdfhbkhafd\x02\x03\x03\x02\x00\x00\x02\x03', b'\x03\x01\x02\x00\x00\x00\x03\x01', 10) == \
        {'scheme': 'xor', 'keysize': 2, 'key': b'\x01\x02', 'modifiers': {'null_preserve': True}, 'offset': 13}

    assert xor.findxor(b'\xfa\xff\x02\x00\x03\x01\x01\x01', b'\x03\x01\x02\x00\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {}, 'offset': 2}
    assert xor.findxor(b'\xfa\xff\x02\x00\x03\x01\x01\x01', b'\x03\x01\x02\x00\x00\x00', 2) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {}, 'offset': 0}
    assert xor.findxor(b'\x17\x06\xa3\x17\x19\xad\x10\xd48\xa1\x18U\xd48Mqpj9ikv~kxt9zxwwvm9{|9klw9pw9]VJ9tv', b'\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x19', 'modifiers': {}, 'offset': 0}

def test_findxor_8byte():
    assert xor.findxor(b'qweyuytewruyqwter\'\xc4\xe1\x00\xb0\xde\x19\xc9\x13\xebF\xbb\xf2\x13\x8c\x94\xb6\xa3\x8d\x9a\xce\xac\xc2\xa7\xac\xab\x93\x9a\xdd\xbf\xc3\xae\xb1\xbe\xde\xd8\xdb\xfe\xdf\xb5\xb0\xea\x97\xd4\x9e\x9a\xe2\x93\xfe\xa7\x91\xde\xdb\xf0\xa0\xcd\xd4\xeekv~kxt9zxwwvm9{|9klw9pw9]VJ9tv', b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode\x2e\x0d\x0d\x0a\x24', 0) == \
        {'scheme': 'xor', 'keysize': 8, 'key': b'\xca\xfe\xba\xbe\xde\xad\xc0\xde', 'modifiers': {}, 'offset': 18}

def test_findxor_rotate_key():
    # offset of pattern found requires key to be rotated to line up with offset 0
    assert xor.findxor(b'qweyu,[\xdc,D\xd2+\x89G\x9aE*\xefe2J-\x15\x024\x14M#\x14C)FA%\x08L+\x12\x02&\x03\x026\x13Ld\x0fLd"m\x17FO+\x02Gjk/NB|9klw9pw9]VJ9tv', b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode\x2e\x0d\x0d\x0a\x24', 0) == \
        {'scheme': 'xor', 'keysize': 3, 'key': b'\x22\x44\x66', 'modifiers': {}, 'offset': 5}

def test_findxor_with_steps():
    assert xor.findxor(b'\x02\x03\x01\x04\x05\x06', b'\x03\x01\x02\x00\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {'step': 1}, 'offset': 0}
    assert xor.findxor(b'\xff\x01\x02\x06\x05\x06\x07', b'\x03\x01\x02\x00\x00\x00', 1) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {'step': 1}, 'offset': 0}
    assert xor.findxor(b'\x02\x01\xfd\xfe\xfd\xfc', b'\x03\x01\x02\x00\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x01', 'modifiers': {'step':-1}, 'offset': 0}

def test_findxor_rolling():
    assert xor.findxor(b'\xa1\x63\x33\x5a\x5a\x5a', b'\x31\xc2\x50\x69\x00\x00', 0) == \
        {'scheme': 'xor', 'keysize': 1, 'key': b'\x90', 'modifiers': {'rolling': True}, 'offset': 0}

