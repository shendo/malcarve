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

import hashlib
import os

from malcarve.payloads import pe

data = os.path.join(os.path.dirname(__file__), 'data')

def md5(content):
    m = hashlib.md5()
    m.update(content)
    return m.hexdigest()

def test_plain():
    buf = open(os.path.join(data, 'plain_64'), 'rb').read()
    res = list(pe.deob(buf, ['plain']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x00
    assert not res['key']
    assert res['scheme'] == 'plain'
    assert res['length'] == 32768

def test_alt_stub():
    buf = open(os.path.join(data, 'alternate_stub_hacked'), 'rb').read()
    res = list(pe.deob(buf, ['plain']))
    print(res)
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x00
    assert not res['key']
    assert res['scheme'] == 'plain'
    assert res['length_with_overlay'] == 31240
    assert res['length'] == 31232

#def test_zeroed_stub():
#    buf = open(os.path.join(data, 'zeroed_32'), 'rb').read()
#    res = list(pe.deob(buf, ['plain']))
#    assert len(res) == 1
#    res = res[0]
#    assert res['offset'] == 0x00
#    assert not res['key']
#    assert res['scheme'] == 'plain'
#    assert res['length_with_overlay'] == 31240
#    assert res['length'] == 31232

def test_xor():
    buf = open(os.path.join(data, 'xor_x19'), 'rb').read()
    res = list(pe.deob(buf, ['xor']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x00
    assert res['key'] == b'\x19'
    assert res['scheme'] == 'xor'
    assert not res['modifiers']
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'
    open('/tmp/original', 'wb').write(res['content'])

def test_xor_nulls():
    buf = open(os.path.join(data, 'xor_x19_null_preserve'), 'rb').read()
    res = list(pe.deob(buf, ['xor']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x00
    assert res['key'] == b'\x19'
    assert res['scheme'] == 'xor'
    assert 'null_preserve' in res['modifiers']
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_xor_nulls_embedded():
    buf = open(os.path.join(data, 'xor_x26_null_preserve_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x0007d0
    assert res['key'] == b'\x26'
    assert res['scheme'] == 'xor'
    assert 'null_preserve' in res['modifiers']
    assert res['length_with_overlay'] == 33232
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_xor_countup():
    buf = open(os.path.join(data, 'xor_x08_countup'), 'rb').read()
    res = list(pe.deob(buf, ['xor_countup']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x00
    assert res['key'] == b'\x08'
    assert res['scheme'] == 'xor'
    assert res['modifiers'] == {'step': 1}
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_xor_countdown_offset():
    buf = open(os.path.join(data, 'xor_xab_countdown_nulls_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor_countdown_null_preserve']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x03e8
    assert res['key'] == b'\xab'
    assert res['scheme'] == 'xor'
    assert res['modifiers'] == {'null_preserve': True, 'step':-1}
    assert res['length_with_overlay'] == 32232
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_2byte_xor_nulls_offset():
    buf = open(os.path.join(data, 'xor_xfe03_nulls_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor_null_preserve']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x03e8
    assert res['key'] == b'\xfe\x03'
    assert res['scheme'] == 'xor'
    assert 'null_preserve' in res['modifiers']
    assert res['length_with_overlay'] == 32232
    assert res['length'] == 31232
    print(repr(res['content'][:100]))
    open('/tmp/borked', 'wb').write(res['content'])

    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_2byte_xor_countup3_nulls_offset():
    buf = open(os.path.join(data, 'xor_xf00d_countup3_nulls_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor_null_preserve']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x0309
    assert res['key'] == b'\xf0\x0d'
    assert res['scheme'] == 'xor'
    assert res['modifiers'] == {'null_preserve': True, 'step': 3}
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_3byte_xor_odd_offset():
    buf = open(os.path.join(data, 'xor_x224466'), 'rb').read()
    res = list(pe.deob(buf, ['xor_null_preserve']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x03e3
    assert res['key'] == b'\x22\x44\x66'
    assert res['scheme'] == 'xor'
    assert not res['modifiers']
    assert res['length'] == 32768
    assert md5(res['content']) == 'c4cb4fdf6369dd1342d2666171866ce5'

def test_4byte_xor_nulls_offset():
    buf = open(os.path.join(data, 'xor_xdeadbeef_nulls_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor_null_preserve']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x03e5
    assert res['key'] == b'\xde\xad\xbe\xef'
    assert res['scheme'] == 'xor'
    assert 'null_preserve' in res['modifiers']
    assert res['length_with_overlay'] == 31247
    assert res['length'] == 31232
    assert md5(res['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_8byte_xor():
    buf = open(os.path.join(data, 'xor_xcafebabedeadc0de_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor']))
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x0186a0
    assert res['key'] == b'\xca\xfe\xba\xbe\xde\xad\xc0\xde'
    assert res['scheme'] == 'xor'
    assert not res['modifiers']
    assert res['length'] == 32768
    assert md5(res['content']) == 'c4cb4fdf6369dd1342d2666171866ce5'

def test_multiple_embedded_xor():
    buf = open(os.path.join(data, 'xor_multi_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['xor']))
    assert len(res) == 3
    assert res[0]['offset'] == 0x04d2
    assert res[0]['key'] == b'\xf0\x0b\xaa'
    assert res[0]['scheme'] == 'xor'
    assert res[0]['modifiers'] == {'null_preserve': True}
    assert res[0]['length_with_overlay'] == 96164
    assert res[0]['length'] == 31232
    assert md5(res[0]['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

    assert res[1]['offset'] == 0x83a4
    assert res[1]['key'] == b'\xab\xcd'
    assert res[1]['scheme'] == 'xor'
    assert res[1]['modifiers'] == {'step': 1}
    assert res[1]['length_with_overlay'] == 63698
    assert res[1]['length'] == 31232
    assert md5(res[1]['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

    assert res[2]['offset'] == 0x010276
    assert res[2]['key'] == b'\xfc'
    assert res[2]['scheme'] == 'xor'
    assert res[2]['modifiers'] == {'step':-2, 'null_preserve': True}
    assert res[2]['length'] == 31232
    assert 'length_with_overlay' not in res[2]
    assert md5(res[2]['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_rolling_xor():
    buf = open(os.path.join(data, 'xor_x90_rolling'), 'rb').read()
    res = list(pe.deob(buf, ['xor']))
    assert len(res) == 1
    assert res[0]['offset'] == 0x00
    assert res[0]['key'] == b'\x90'
    assert res[0]['scheme'] == 'xor'
    assert res[0]['modifiers'] == {'rolling': True}
    assert res[0]['length'] == 31232
    assert md5(res[0]['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

def test_rol():
    buf = open(os.path.join(data, 'rol3_embedded'), 'rb').read()
    res = list(pe.deob(buf, ['rol']))
    assert len(res) == 1
    assert res[0]['offset'] == 0x2710
    assert res[0]['key'] == b'\x03'
    assert res[0]['scheme'] == 'rol'
    assert res[0]['modifiers'] == {}
    assert res[0]['length'] == 31232
    assert md5(res[0]['content']) == '71cc09e8f88bec2186aa6aee4b2cdaeb'

