BINDIR?=/tmp/
DESTDIR?=/

.PHONY: build install uninstall clean

build: dist/setup
	obuild build

dist/setup:
	obuild configure

install:
	install -m 0755 dist/build/vncproxy/vncproxy ${DESTDIR}${BINDIR}

uninstall:
	rm -f ${BINDIR}/vncproxy

clean:
	obuild clean

