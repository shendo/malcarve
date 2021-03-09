malcarve
========

Obfuscated payload extractor for malware samples

|build_status| |pypi_version|


Overview
--------

``malcarve`` is a tool for detecting and extracting obfuscated, embedded content
from files.  In particular it is targeted at extracting malicious payloads such
as those contained in malware attack documents and droppers.

A command-line utility is included alongside a simple Python API.
Further, a web API is provided as an example scanning web service. 


Getting Started
---------------
Install using ``pip``: ::

	pip install malcarve

Command-line usage: ::

	malcarve [--extract [--output-dir <output_dir>]] <file1> <file2> ...


Example Webservice: ::

	malcarve-web [-H <interface_address>] [-p port_number]


Config can be updated by copying malcarve/conf/malcarve.conf to
~/.malcarve/malcarve.conf and changing settings as desired.


History
-------

Malcarve was originally written several years ago.  It was predominantly
targeted at extracting XOR'ed PE files from Flash, Word and PDF documents,
which were commonly being exploited at the time.

After needing a similar capability again recently, I've started reviving the
code (it's still a bit of a mess) along with migrating to python3.  This also
comes with a newer focus towards macro'ed documents and embedded urls/other
file types and obfuscation techniques.

This is still a work in progress but has been released in the hope
that others may find it useful (no warranty given or implied).


Existing Tools
--------------

There are many great tools and published literature already in this space. 
``malcarve`` borrows heavily, and is inspired from techniques
discussed or available in the following:

   * `XORSearch`_
   * `Playing With Others Blog`_
   * `Deobfuscating Embedded Malware using Probable-Plaintext Attacks`_
   * `unXOR`_
   * `balbuzard`_

The motivation in writing yet another deobfuscator was the need to not only
detect obfuscated patterns and payloads but to also extract/carve that content
automatically.

Some tools already handled this but would only perform a subset of the schemes
or file types needed.


Features
--------

   * Deobfuscation/carving of Windows PE Files, Zip and Ole2 files
   * Experimental carving of PDF and other formats (check config file)
   * Obfuscated and embedded URL extraction
   * Multibyte XOR deobfuscation
   * XOR modifiers countup, countdown, preserve nulls
   * Scans inside common stream encodings like base64 and deflate

Future Work:

More than happy for feedback, discussion and pull requests...

   * Handle various other obfuscation techniques used in VBA macros
   * Performance enhancements by overhauling pattern checks into single pass
   * Extraction of general obfuscated scripts (eg. powershell, javascript)
   * Fix poor performance of deflate and ascii based stream handling
   * Write proper documentation


Issues
------

Source code for ``malcarve`` is hosted on `GitHub`_. Any bug reports or feature
requests can be made using GitHub's `issues system`_.


.. _GitHub: https://github.com/shendo/malcarve
.. _issues system: https://github.com/shendo/malcarve/issues

.. |build_status| image:: https://secure.travis-ci.org/shendo/malcarve.png?branch=master
   :target: https://travis-ci.org/shendo/malcarve
   :alt: Current build status

.. |pypi_version| image:: https://pypip.in/v/malcarve/badge.png
   :target: https://pypi.python.org/pypi/malcarve
   :alt: Latest PyPI version

.. _Playing With Others Blog: https://playingwithothers.com/2012/12/20/decoding-xor-shellcode-without-a-key/
.. _XORSearch: https://blog.didierstevens.com/programs/xorsearch/
.. _Deobfuscating Embedded Malware using Probable-Plaintext Attacks: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.675.2542&rep=rep1&type=pdf
.. _unXOR: https://github.com/tomchop/unxor
.. _balbuzard: https://bitbucket.org/decalage/balbuzard
