
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

