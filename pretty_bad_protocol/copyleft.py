# -*- coding: utf-8 -*-
#
# This file is part of python-gnupg, a Python interface to GnuPG.
# Copyright © 2013 Isis Lovecruft, <isis@leap.se> 0xA3ADB67A2CDB8B35
#           © 2013 Andrej B.
#           © 2013 LEAP Encryption Access Project
#           © 2008-2012 Vinay Sajip
#           © 2005 Steve Traugott
#           © 2004 A.M. Kuchling
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The name(s) of the copyright holder(s) may not be used to endorse or
#       promote products derived from this software without specific prior
#       written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''copyleft.py
--------------
Copyright information for python-gnupg.
'''

from __future__ import absolute_import

from . import _util


authors = { 'lovecruft_isis': _util.author_info(
                'Isis Agora Lovecruft', 'isis@leap.se', '0xA3ADB67A2CDB8B35'),

            'sajip_vinay': _util.author_info(
                'Vinay Sajip', 'vinay.sajip@gmail.com', '0xDE6EF0B2'),

            'traugott_steve': _util.author_info(
                'Steve Traugott', 'stevegt@terraluna.org'),

            'kuchling_am': _util.author_info(
                'A.M. Kuchling', 'amk@amk.ca'), }

copyright = """\
Copyright © 2013 Isis Lovecruft, <isis@leap.se> 0xA3ADB67A2CDB8B35
          © 2013 Andrej B.
          © 2013 LEAP Encryption Access Project
          © 2008-2012 Vinay Sajip
          © 2005 Steve Traugott
          © 2004 A.M. Kuchling
All rights reserved.
See included LICENSE or ``print(gnupg.__license__)`` for full license."""

disclaimer = """\
This file is part of python-gnupg, a Python wrapper around GnuPG.
%s

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * The name(s) of the copyright holder(s) may not be used to endorse or
      promote products derived from this software without specific prior
      written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
""" % (copyright,)

txcopyright = """\
Where stated, parts of this program were taken from Twisted, which is
licensed as follows:

Twisted, the Framework of Your Internet
Copyright © 2001-2013 Twisted Matrix Laboratories.
See LICENSE for details.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."""


full_text = "%s\n\n%s" % (disclaimer, txcopyright)
