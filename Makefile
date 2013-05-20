
ctags:
	ctags -R *.py

etags:
	find . -name "*.py" -print | xargs etags

cleanup-src:
	cd src && \
		rm -f \#*\# && \
		rm -f ./*.pyc && \
		rm -f ./*.pyo

cleanup-tests:
	cd tests && \
		rm -f \#*\# && \
		rm -f ./*.pyc && \
		rm -f ./*.pyo

cleanup-build:
	mkdir buildnot
	rm -rf build*

cleantest: cleanup-src cleanup-tests cleanup-build
	mkdir -p tests/tmp
	touch placeholder.log
	rm -rf tests/tmp
	rm *.log

test: cleantest
	python tests/test_gnupg.py parsers basic genkey sign listkeys crypt keyrings import

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
