#!/usr/bin/env python
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
from __future__ import print_function
from __future__ import unicode_literals

import binascii
from hashlib import md5
import importlib
from itertools import chain
import os
import quopri
import timeit

import begin
import progressbar

from malcarve.config import Config


def class_for_name(class_name):
    """
    Dynamically load the given class name.

    :param class_name: str with class name to import/load.
    :return: Loaded Class object.
    """
    module_name, class_name = class_name.rsplit('.', 1)
    module = importlib.import_module(module_name)
    return getattr(module, class_name)

def get_filename(infile, carving, overlay=False):
    """
    Generate a suitable output filename for the carved object.
    
    :param infile: Input filename object was carved from
    :param carving: Dictionary of extracted object
    :param overlay: Is filename for saving with or without overlay included
    :return: String containing output filename
    """
    offset = '0x%08x' % carving['offset']
    fname = "%s.%s" % (os.path.basename(infile), offset)
    if carving.get('encoding'):
        fname += '.%s' % carving['encoding']
    if carving.get('stream_offset'):
        fname += '.0x%08x' % carving['stream_offset']
    fname += '.%s' % carving['scheme']
    if carving.get('key'):
        fname += '.%s' % binascii.hexlify(carving['key']).decode()
    if overlay:
        fname += '.with_overlay'
    return fname

class Scanner(object):
    """
    Main scanning object.
    
    Will derive configuration from default conf file locations unless
    overridden.
    """
    def __init__(self, config=None):
        self.config = config or Config()
        self.embedded_only = self.config.embedded_only

        self.deobfuscators = {}
        for x in self.config.deobfuscators.values():
            d = class_for_name(x.class_name)(x.name, x.description, x.schemes, x.modifiers, x.max_keysize, **x.other)
            self.deobfuscators[x.name] = d

        self.payloads = {}
        for x in self.config.payloads.values():
            p = class_for_name(x.class_name)(x.name, x.scan_min, x.scan_max, x.min_size, x.validation, **x.other)
            for d in x.deobs:
                p.add_scheme(self.deobfuscators[d])
            for pat in x.patterns:
                p.add_pattern(pat)
            self.payloads[p.name] = p

        self.decoders = {}
        for x in self.config.decoders.values():
            d = class_for_name(x.class_name)(x.name)
            self.decoders[x.name] = d

    def get_streams(self, stream, depth=0):
        """
        Recursively scan stream data, decoding additional streams to scan.

        :param stream: Input stream object to scan for additional streams.
        :param depth: How far has this recursed.
        :return: Generator of decoded streams to scan for obfuscated objects.
        """
        if not depth:
            stream = {
                'encoding': None,
                'offset': 0,
                'stream_id': 'file',
                'stream': stream,
                'parent': None,
            }
            yield stream

        if depth >= self.config.max_stream_depth:
            return

        for d in self.decoders.values():
            for s in d.decode(stream['stream'], self.get_stream_encodings(stream)):
                if all((x == s['stream'][0] for x in s['stream'])):
                    continue
                s['parent'] = stream
                yield s
                for sub in self.get_streams(s, depth+1):
                    yield sub

    def get_stream_encodings(self, stream):
        """
        Helper method to return the current encoding chain as a dotted string.
        
        :param stream: Stream object to return encoding for.
        :return: str of enodings applied or None.
        """
        steps = []
        s = stream
        while True:
            if s['encoding']:
                steps.append(s['encoding'])
            if not s['parent']:
                break
            s = s['parent']
        if steps:
            return '.'.join(steps[::-1])
        return None
    
    def scan_buffer(self, buf, log=False):
        """
        Entry point to scan a buffer of bytes for embedded objects.

        :param buf: Bytes object containing data to scan.
        :return: Generator of matched result dicts.
        """
        dedupe = set()
        # If input is a mime encoded format like email or mht, quoted-printable can screw with plain
        # extraction of url's, etc... we don't really want to implement as a sub stream or we'll get
        # the broken urls, etc. from the original content still.  It can also create havoc with b64 data.
        # Force conversion upfront.  TODO: how do we correct file/match offsets when this triggers?
        if b'quoted-printable' in buf[:10000]: # and all(c < 0x7f for c in buf):
            if log:
                print("Forcing quoted-printable decode of input")
            buf = quopri.decodestring(buf)
            # TODO: invetigate if this could break email with mix of quopri and base64?
        if log:
            print("Scanning sub-streams and their permutations...")
            it = progressbar.progressbar(self.get_streams(buf), redirect_stdout=True)
        else:
            it = self.get_streams(buf)

        for stream in it:
            #print("Stream Encoding %s %s %d %s" % (stream['stream_id'], self.get_stream_encodings(stream) or 'none', len(stream['stream']), stream['stream'][:50]))
            for p in self.payloads.values():
                for res in chain(self.check_stream_plaintext(p, stream), p.deob(stream['stream'])):

                    # only include if deemed 'interesting'
                    if self.embedded_only and not res['offset'] \
                        and not stream['encoding'] \
                        and res['scheme'] == 'plain':
                        continue
                    h = md5(res['content']).hexdigest()
                    if stream['encoding']:
                        res['encoding'] = self.get_stream_encodings(stream)
                        res['stream_offset'] = res['offset']
                        res['offset'] = stream['offset']
                        res['stream_id'] = stream['stream_id']
                    dedupe_key = (res['scheme'], res['key'], stream['encoding'],
                        res.get('stream_offset'), res['offset'], h)
                    if dedupe_key in dedupe:
                        continue
                    # ignore no-op encoding of hex/reverse/rol4
                    if res.get('encoding') and 'base16' in res['encoding'] \
                            and 'reverse' in res['encoding'] \
                            and res['scheme'] == 'rol' and res['key'] == b'\x04':
                        continue
                    dedupe.add(dedupe_key)
                    yield res

    def check_stream_plaintext(self, payload, stream):
        """
        Check if the stream is a payload, without any further deobfuscation.

        Normally, paylaods would get picked up by ^ 0x0 anyway but
        this may find additional embedded objects that don't match
        known patterns (eg. PE with dos stub stripped, urls with mixed casing).
        """
        if not stream['encoding']:
            return
        start, end = payload.validator.validate(stream['stream'])
        if end > 0:
            res = {
                'offset': start,
                'content': stream['stream'],
                'scheme': 'plain',
                'payload_type': payload.name,
                'pattern': b'',
                'length': end - start,
                'key': None,
                'modifiers': {},
            }
            if end < len(stream['stream']):
                res['content_with_overlay'] = stream['stream']
                res['length_with_overlay'] = len(stream['stream'])
            yield res

    def scan_path(self, path):
        """
        Scan the file at the supplied path.
        """
        with open(path, 'rb') as tmp:
            for x in self.scan_buffer(tmp.read()):
                yield x


@begin.start(auto_convert=True)
def main(extract=False, output_dir=os.getcwd(), *files):
    """
    Command-line entrypoint to scan a list of files.
    
    Will scan any filepaths specified and print details of
    detected embedded payloads.
    
    :param extract: Whether to write out deobfuscated payloads to file.
    :param output_dir: Where to write out deobfuscated payloads.
    :param files: List of files to scan.
    """
    scanner = Scanner()
    for x in files:
        try:
            buf = open(x, 'rb').read()
            start = timeit.default_timer()
            print("%s (%d bytes):" % (x, len(buf)))
            for d in scanner.scan_buffer(buf, log=True):
                print("\tOffset: 0x%08x Length: %i" % (d['offset'], d['length']))
                if d.get('encoding'):
                    print("\tStream Id: %s Offset: 0x%08x" % (d['stream_id'], d['stream_offset']))
                    print("\tStream Encoding: %s" % d['encoding'])
                key = d['key']
                if key:
                    key = '%s' % binascii.hexlify(d['key']).decode()
                print("\tPayload: %s" % d['payload_type'])
                print("\tScheme: %s %s %s" % (d['scheme'], key, d['modifiers']))
                if len(d['content']) > 200:
                    print("\tSample: %s\n" % repr(d['content'][:35]))
                else:
                    print("\tContent: %s\n" % repr(d['content']))
                if extract:
                    with open(os.path.join(output_dir,
                                get_filename(x, d)), 'wb') as tmp:
                        tmp.write(d['content'])
                    if d.get('content_with_overlay'):
                        with open(os.path.join(output_dir,
                                    get_filename(x, d, True)), 'wb') as tmp:
                            tmp.write(d['content_with_overlay'])

            # print("\tDuration: %02d ms\n" % ((timeit.default_timer() - start) * 1000))
        except Exception as ex:
            print("Unable to process %s: %s" % (x, str(ex)))
            raise ex

