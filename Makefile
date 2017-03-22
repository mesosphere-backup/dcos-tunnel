all: env test packages

clean:
	bin/clean.sh

clean-cache:
	find . -name '*.pyc' | xargs rm
	find . -name '__pycache__' | xargs rm -rf

env:
	bin/env.sh

test: env
	${SHELL} -c ". env/bin/activate; \
		bin/test.sh"

test-binary: test
	${SHELL} -c ". env/bin/activate; \
		bin/test-binary.sh"

test-binary-debug: env
	${SHELL} -c ". env/bin/activate; \
		bin/test-binary.sh $(test)"

packages: env
	${SHELL} -c ". env/bin/activate; \
		bin/packages.sh"

binary: clean env packages
	${SHELL} -c ". env/bin/activate; \
		pyinstaller binary/binary.spec"
