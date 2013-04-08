
clean:
	rm -f \#*\#
	rm -f ./*.pyc
	rm -f ./*.pyo

cleantest: clean
	mkdir -p keys
	touch placeholder.log
	rm -rf keys
	rm *.log

test: cleantest 
	python test_gnupg.py basic

install: 
	python setup.py install --record installed-files.txt

uninstall:
	cat installed-files.txt | sudo xargs rm -rf

clean-docs:
	sphinx-apidoc -o docs -F -A "Isis Agora Lovecruft" -H "python-gnupg" -V 0.3.1 -R 0.3.1 .

docs:
	cd docs
	make clean
	make html

venv:
	-source /usr/shared/python/ns/virtualenvwrapper.sh && mkvirtualenv -a "$PWD" --unzip-setuptools --distribute python-gnupg
