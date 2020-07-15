xorsearch: XORSearch.o
	gcc -o xorsearch XORSearch.c
	strip xorsearch

clean:
	rm -f XORSearch.o xorsearch

install: xorsearch
	install -D xorsearch $(DESTDIR)/usr/bin/xorsearch
