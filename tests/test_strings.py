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

from malcarve.payloads import strings


def test_plain():
    buf = b'random url http://malware.callback.net/gate.php'
    res = list(strings.deob(buf, ['plain']))
    print(res)
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x0b
    assert not res['key']
    assert res['scheme'] == 'plain'
    assert res['length'] == 36
    assert res['content'] == b'http://malware.callback.net/gate.php'

def test_xor():
    buf = b'xx}xfqmmi#66txunxk|7zvt'
    res = list(strings.deob(buf, ['xor']))
    print(res)
    assert len(res) == 1
    res = res[0]
    assert res['offset'] == 0x05
    assert res['key'] == b'\x19'
    assert res['scheme'] == 'xor'
    assert not res['modifiers']
    assert res['length'] == 18
    assert res['content']== b'http://malware.com'

