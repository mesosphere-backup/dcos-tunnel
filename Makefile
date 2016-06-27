all: env test packages

clean:
	bin/clean.sh

env:
	bin/env.sh

test:
	bin/test.sh

packages:
	bin/packages.sh

binary: clean env packages
	pyinstaller binary/binary.spec

local-binary: clean env packages
	sh -c "source env/bin/activate; \
	pip install pyinstaller==3.1.1; \
	pyinstaller binary/binary.spec"
