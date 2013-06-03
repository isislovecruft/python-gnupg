#!/bin/bash
# -*- coding: utf-8 -*-
#
# This file is part of python-gnupg, a Python wrapper around GnuPG.
# Copyright © 2013 Isis Lovecruft, Andrej B.
#           © 2008-2012 Vinay Sajip
#           © 2005 Steve Traugott
#           © 2004 A.M. Kuchling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

project=python-gnupg
VENV=$(which virtualenv)
WRPR=$(which virtualenvwrapper.sh)


if ! test -n "$VENV" ; then
    printf "Couldn't find virtualenv. Are you sure it's installed?"
    exit 1
fi

if ! test -n "$WRPR"; then
    printf "Couldn't find virtualenvwrapper. Are you sure it's installed?"
    exit 1
fi

test -r "$WRPR" && . $WRPR
okay=$?

if test "$okay" -eq 0 ; then
    printf "Using %s as WORKON_HOME for the new virtualenv...\n" "$PWD"
    printf"What should the name of the new virtualenv be? (default: '%s')\n" "$project"
    read -p"Name for this virtualenv?: " name
    if test -z "$name"; then
        name="$project"
    fi
    printf "Using '$name' as our project's name..."
    printf "Creating virtualenv..."
    mkvirtualenv -a "$PWD" --no-site-packages \
        --distribute --prompt="(gnupg)" "$name"
    exit $?
else
    printf "Something went wrong..."
    printf "Exit code %d from mkvirtualenv." "$okay"
    exit $okay
fi
