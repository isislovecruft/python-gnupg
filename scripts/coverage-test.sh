#!/cin/bash
# -*- coding: utf-8 -*-

python -m gnupg.test.test_gnupg

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
