EXE		= signsrch
CFLAGS	+= -s -O2
PREFIX	= usr
BINDIR	= $(PREFIX)/bin
SRC		= $(EXE).c

all:
	$(CC) $(CFLAGS) -c disasm.c
	$(CC) $(CFLAGS) -c asmserv.c
	$(CC) $(SRC) $(CFLAGS) -o $(EXE) *.o -lpthread

install:
	install -m 755 -d $(BINDIR)
	install -m 755 $(EXE) $(BINDIR)/$(EXE)

.PHONY:
	install
