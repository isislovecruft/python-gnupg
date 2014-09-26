#!/usr/bin/env python
# -*- coding: utf-8 -*-

import inspect
import os

here = inspect.getabspath(inspect.currentframe()).rsplit('/', 1)[0]
unittests = "basic encodings parsers keyrings listkeys genkey sign crypt"
run_test = "python -m {}/test_gnupg.py {}".format(here, unittests)

os.system(run_test)

#HERE=$(dirname $0)
#python -m $HERE/test_gnupg.py basic encodings parsers keyrings listkeys \
#    genkey sign crypt
#
# python-coverage run $HERE/test_gnupg.py \
#     parsers basic encodings genkey sign listkeys crypt keyrings import && \
#     #python-coverage report --include=$INSTALL_DIR && \
#     #python-coverage html -d ./coverage --include=$INSTALL_DIR && \
#     python-coverage report && \
#     python-coverage html -d ./coverage && \
#     firefox ./coverage/index.html
