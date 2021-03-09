from malcarve.streams import ascii


def test_charcodes():
    d = ascii.ChrDecoder('charcodes')
    s = list(d.decode(b'>LOAD "*",8,1 any c64 fans?'))
    assert len(s) == 0

    s = list(d.decode(b'123,255,1,23,67,90,0,0'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 0
    assert s['encoding'] == 'charcodes'

    s = list(d.decode(b'asdasdjlk 123,255,1,23,67,90,0,0; asd \ndsdasd'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 10

    s = list(d.decode(b'asdasdjlk 123,255,1,23,67,90,0,0; asd \ndsdasd 123,255,1,23,67,90,0,1'))
    assert len(s) == 2
    s0 = s[0]
    assert s0['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s0['offset'] == 10
    s1 = s[1]
    assert s1['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x01'
    assert s1['offset'] == 46
 
    s = list(d.decode(b'asdasdjlk 123.255.1.23.67.90.0.0; asd \ndsdasd'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 10

    s = list(d.decode(b'asdasdjlk 123, 255, 1, 23, 67, 90, 0, 0; asd \ndsdasd'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 10

    s = list(d.decode(b'asdasdjlk Chr(123), Chr(255), Chr(1), Chr(23), Chr(67), Chr(90), Chr(0), Chr(0); asd \ndsdasd'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 10

    s = list(d.decode(b'asdasdjlk = Chr(123) & Chr(255) & Chr(1) & Chr(23) & Chr(67) & Chr(90) & Chr(0) & Chr(0) asd \ndsdasd'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 12

    # cheeky oblique rat docs
    s = list(d.decode(b'asdasdjlk 123O255O1O23O67O90O0O0 asd \ndsdasd'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x7b\xff\x01\x17\x43\x5a\x00\x00'
    assert s['offset'] == 10


def test_hex():
    d = ascii.HexDecoder('base16')
    s = list(d.decode(b'123,255,1,23,67,90,0,0'))
    assert len(s) == 0

    s = list(d.decode(b'12,25,1f,23,67,90,00,00'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x12\x25\x1f\x23\x67\x90\x00\x00'
    assert s['offset'] == 0
    assert s['encoding'] == 'base16'

    s = list(d.decode(b'ZZ12251f2367900000ZZ'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'\x12\x25\x1f\x23\x67\x90\x00\x00'
    assert s['offset'] == 2
    assert s['encoding'] == 'base16'

    s = list(d.decode(b'ZZ12251f2367900000ZZZZ12251f2367900001ZZ'))
    assert len(s) == 3 # each hex run separate and also a combined output
    s0 = s[0]
    assert s0['stream'] == b'\x12\x25\x1f\x23\x67\x90\x00\x00'
    assert s0['offset'] == 2
    assert s0['encoding'] == 'base16'

    s1 = s[1]
    assert s1['stream'] == b'\x12\x25\x1f\x23\x67\x90\x00\x01'
    assert s1['offset'] == 22
    assert s1['encoding'] == 'base16'

    s2 = s[2]
    assert s2['stream'] == b'\x12\x25\x1f\x23\x67\x90\x00\x00\x12\x25\x1f\x23\x67\x90\x00\x01'
    assert s2['offset'] == 2
    assert s2['encoding'] == 'base16'

    s = list(d.decode(b'12251f2367900000\r\n12251f2367900001\r\n'))
    assert len(s) == 1 # whitespace is ignored to produce one run of hex
    s0 = s[0]
    assert s0['stream'] == b'\x12\x25\x1f\x23\x67\x90\x00\x00\x12\x25\x1f\x23\x67\x90\x00\x01'
    assert s0['offset'] == 0
    assert s0['encoding'] == 'base16'


def test_base64():
    d = ascii.B64Decoder('base64')
    s = list(d.decode(b'123,255,1,23,67,90,0,0'))
    assert len(s) == 0

    s = list(d.decode(b'QXJlIHlvdSBlbnRlcnRhaW5lZCE/'))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'Are you entertained!?'
    assert s['offset'] == 0
    assert s['encoding'] == 'base64'

    s = list(d.decode(b'\x01\x02;;QXJlIHlvdSBlbnRlcnRhaW5lZCE/;;='))
    assert len(s) == 1
    s = s[0]
    assert s['stream'] == b'Are you entertained!?'
    assert s['offset'] == 4
    assert s['encoding'] == 'base64'
