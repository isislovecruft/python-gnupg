.PHONY=all
all: uninstall install test

ctags:
	ctags -R *.py

etags:
	find . -name "*.py" -print | xargs etags

# Sanitation targets -- clean leaves libraries, executables and tags
# files, which clobber removes as well
pycremoval:
    find . -name '*.py[co]' -exec rm -f {} ';'

cleanup-src: pycremoval
	cd gnupg && rm -f \#*\#

cleanup-tests: cleanup-src
	cd $(TESTDIR) && rm -f \#*\#
	mkdir -p gnupg/test/tmp
	mkdir -p gnupg/test/logs

cleanup-tests-all: cleanup-tests
	rm -rf tests/tmp

cleanup-build:
	mkdir buildnot
	rm -rf build*

test: cleanup-src cleanup-tests
	which gpg
	gpg --version
	which gpg2
	gpg2 --version
	which gpg-agent
	which pinentry
	which python
	python --version
	which pip
	pip --version
	pip list
	python tests/test_gnupg.py parsers basic encodings genkey sign listkeys crypt keyrings import

install: 
	python setup.py install --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | sudo xargs rm -rf

cleandocs:
	sphinx-apidoc -F -A "Isis Agora Lovecruft" -H "python-gnupg" -V 0.4.0 -R 0.4.0 -o docs src/ tests/

docs:
	cd docs
	make clean
	make html

venv:
	-source /usr/shared/python/ns/virtualenvwrapper.sh && mkvirtualenv -a "$PWD" --no-site-packages --unzip-setuptools --distribute python-gnupg
