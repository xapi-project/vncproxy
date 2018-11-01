.PHONY: build release install uninstall clean reindent

build:
	dune build @install

release:
	dune build --profile=release @install

install:
	dune install --profile=release

uninstall:
	dune uninstall --profile=release

clean:
	dune clean

reindent:
	ocp-indent -i **/*.ml*
