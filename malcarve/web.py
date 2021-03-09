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
from __future__ import unicode_literals

try:
    from gevent import monkey
    monkey.patch_all()
    SERVER = 'gevent'
except ImportError:
    SERVER = 'wsgiref'

import argparse
import base64
import binascii
from datetime import datetime
import hashlib
import json
import logging
import os

from bottle import request, response, route, run, default_app
from jinja2.environment import Environment
from jinja2.loaders import FileSystemLoader

from malcarve import scan
from malcarve.version import __version__

# Load templates
root = os.path.join(os.path.dirname(__file__), "html")
env = Environment()
env.loader = FileSystemLoader(root)
env.filters['b64encode'] = base64.b64encode
env.filters['b64decode'] = base64.b64decode
env.filters['utf8decode'] = lambda x: x.decode('utf8')
env.filters['hexlify'] = binascii.hexlify

jsondate = lambda obj: obj.isoformat() if isinstance(obj, datetime) else None
scanner = scan.Scanner()


def scan_file(infile, filename):
    """
    Scan the given data buffer and return a dictionary of results.
    """
    m = hashlib.md5()
    results = {'filename': filename,
               'status': 'Failed',
               'apiversion': __version__,
               'start': datetime.utcnow(),
               'carved': [],
               }
    try:
        # read whole thing into mem
        buf = infile.read()
        m.update(buf)
        results['md5'] = m.hexdigest()
        results['filesize'] = len(buf)
        # make human readable
        for r in scanner.scan_buffer(buf):
            if r.get('content'):
                r['content'] = base64.b64encode(r['content']).decode('utf-8')
                r['content_filename'] = scan.get_filename(filename, r)
            if r.get('content_with_overlay'):
                r['content_with_overlay'] = base64.b64encode(r['content_with_overlay']).decode('utf-8')
                r['content_with_overlay_filename'] = scan.get_filename(filename, r, True)
            if r.get('key'):
                r['key'] =  '0x' + binascii.hexlify(r['key']).decode('utf-8')
            if r.get('pattern'):
                r['pattern'] = repr(r['pattern'])[2:-1]
            results['carved'].append(r)
        # successfully processed but not necessarily carved anything
        results['status'] = 'Success'
    except Exception as ex:
        results['error'] = str(ex)
    finally:
        results['finish'] = datetime.utcnow()
        results['duration'] = (results['finish'] - results['start']).total_seconds()
        infile.close()
    return results

@route("/", name="home")
def home():
    """
    Main page, displays a submit file form.
    """
    template = env.get_template("submit.html")
    return template.render(base)


@route("/submit", method="POST", name="submit")
def submit_and_render():
    """
    Blocking POST handler for file submission.
    Runs malcarve on supplied file and returns results as rendered html.
    """
    data = request.files.file
    template = env.get_template("results.html")
    if not data:
        pass
    results = scan_file(data.file, data.filename)
    results.update(base)
    return template.render(results)

@route("/api/submit", method="POST", name="api_submit")
def api_submit():
    """
    Blocking POST handler for file submission.
    Runs malcarve on supplied file and returns results as json text.
    """
    data = request.files.file
    response.content_type = b'application/json'
    if not data or not hasattr(data, 'file'):
        return json.dumps({"status": "Failed", "stderr": "Missing form params"})
    return json.dumps(scan_file(data.file, data.filename), default=jsondate, indent=4)

@route("/api", name="api")
def api():
    """
    Display an api usage/help page.
    """
    template = env.get_template("api.html")
    return template.render(base)


def main():
    """
    Main entrypoint for command-line webserver.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Web server Host address to bind to",
                        default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Web server Port to bind to",
                        default=8080, action="store", required=False)
    args = parser.parse_args()

    logging.basicConfig()
    run(host=args.host, port=args.port, reloader=True, server=SERVER, debug=True)

# WSGI and template url support
application = default_app()
base = {'get_url': application.get_url}

if __name__ == '__main__':
    main()
