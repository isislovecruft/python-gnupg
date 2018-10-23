SHELL=/bin/sh
TESTDIR=./pretty_bad_protocol/test
TESTHANDLE=$(TESTDIR)/test_gnupg.py
FILES=$(SHELL find ./pretty_bad_protocol/ -name "*.py" -printf "%p,")
PYTHON=$(SHELL which python)
PYTHON3=$(SHELL which python3)
PKG_NAME=pretty_bad_protocol
DOC_DIR=docs
DOC_BUILD_DIR:=$(DOC_DIR)/_build
DOC_HTML_DIR:=$(DOC_BUILD_DIR)/html
DOC_BUILD_ZIP:=$(PKG_NAME)-docs.zip

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
	cd pretty_bad_protocol/ && rm -f \#*\#

cleanup-tests: cleanup-src
	cd $(TESTDIR) && rm -f \#*\#
	mkdir -p $(TESTDIR)/tmp
	mkdir -p $(TESTDIR)/logs

cleanup-tests-all: cleanup-tests
	rm -rf tests/tmp

cleanup-build:
	-rm MANIFEST
	-rm -rf build

cleanup-dist:
	-rm -rf dist

clean: cleanup-build cleanup-tests-all cleanup-src

dist-clean: clean cleanup-dist

# it's not strictly necessary that gnupg2, gpg-agent, pinentry, or pip be
# installed, so ignore error exit statuses for those commands
test-before: cleanup-src cleanup-tests
	which gpg && gpg --version
	-which gpg2 && gpg2 --version
	-which gpg-agent
	-which pinentry
	which python && python --version
	-which pip && pip --version && pip list

test-run: test-before
	python $(TESTHANDLE) \
		basic \
		encodings \
		parsers \
		keyrings \
		listkeys \
		genkey \
		sign \
		crypt \
		expiration \
		signing

py3k-test-run: test-before
	python3 $(TESTHANDLE) \
		basic \
		encodings \
		parsers \
		keyrings \
		listkeys \
		genkey \
		sign \
		crypt
#		expiration \
#		signing

coverage-run: test-before
	coverage run --rcfile=".coveragerc" $(PYTHON) $(TESTHANDLE) \
		basic \
		encodings \
		parsers \
		keyrings \
		listkeys \
		genkeys \
		sign \
		crypt \
		expiration \
		signing

py3k-coverage-run: test-before
	coverage run --rcfile=".coveragerc" $(PYTHON3) $(TESTHANDLE) \
		basic \
		encodings \
		parsers \
		keyrings \
		listkeys \
		genkeys \
		sign \
		crypt \
		expiration \
		signing

coverage-report:
	coverage report --rcfile=".coveragerc"

coverage-html:
	coverage html --rcfile=".coveragerc"

clean-test:
	-mv $(TESTDIR)/*.log $(TESTDIR)/logs/
	-rm $(TESTDIR)/logs/placeholder.log
	-rm $(TESTDIR)/random_seed*

test: test-run

py3k-test: py3k-test-run

coverage: coverage-run coverage-report coverage-html clean-test

py3k-coverage: py3k-coverage-run coverage-report coverage-html clean-test

install: 
	python setup.py install --record installed-files.txt
py3k-install:
	python3 setup.py install --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf
py3k-uninstall: uninstall

reinstall: uninstall install
py3k-reinstall: py3k-uninstall py3k-install

docs-clean:
	-rm -rf $(DOC_BUILD_DIR)

docs-completely-new:
	sphinx-apidoc -F -A "isis agora lovecruft" -H "pretty-bad-protocol" -o $(DOC_DIR) pretty_bad_protocol/ tests/

docs-html:
	cd $(DOC_DIR) && make clean && make html

docs-zipfile: docs-html
	cd $(DOC_HTML_DIR) && { find . -name '*' | zip -@ -v ../$(DOC_BUILD_ZIP) ;};
	@echo "Built documentation in $(DOC_BUILD_DIR)/$(DOC_BUILD_ZIP)"

upload: cleanup-build
	python setup.py bdist_egg upload --sign
	#python setup.py bdist_wheel upload --sign
	python setup.py sdist --formats=gztar,zip upload --sign
