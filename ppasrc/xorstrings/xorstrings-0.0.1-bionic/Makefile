xorstrings: XORStrings.o
	gcc -o xorstrings XORStrings.c

clean:
	rm -f XORStrings.o xorstrings

install: xorstrings
	install -D xorstrings $(DESTDIR)/bin/xorstrings
