include common.mk

all:
	$(MKDIR) lib bin
	$(MAKE) -C src
	$(MAKE) -C test
	$(MAKE) -C sample

test:
	$(MAKE) -C test test

sample:
	$(MAKE) -C sample

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C sample clean

PREFIX?=/usr/local
install:
	$(MKDIR) $(PREFIX)/include/cybozu
	cp -a include/cybozu/ $(PREFIX)/include/

.PHONY: sample clean

