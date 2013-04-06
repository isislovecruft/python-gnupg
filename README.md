# python-gnupg #
================

Fork of python-gnupg-0.3.2, patched to remove Popen([...], shell=True).

### Installation ###
--------------------
To install this package from this git repository, do:

```
git clone https://github.com/isislovecruft/python-gnupg.git
cd python-gnupg
make install
make test
```

Optionally to build the documentation after installation, do:
```
make docs
```

To get started using python-gnupg's API, see the documentation online at [XXX
FIXME add readthedocs link](), and import the module like so:
```
>>> import gnupg
```


To install this package from a tarballed source distribution, do the following:

1. Extract all the files in the distribution archive to some directory on your system.
2. In that directory, run "python setup.py install".
3. Optionally, run "python test_gnupg.py" to ensure that the package is working as expected.
