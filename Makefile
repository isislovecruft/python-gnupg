
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
	python setup.py install

docs:
	sphinx-apidoc -o docs -F -A "Isis Agora Lovecruft" -H "python-gnupg" -V 0.3.1 -R 0.3.1 .
	cd docs
	make html
