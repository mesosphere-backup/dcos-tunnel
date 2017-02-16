#!/bin/bash -e

single_test="$1"

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/.."

cd $BASEDIR

PATH=$(pwd)/dist:$PATH
[ -n "$DCOS_CONFIG" ] && cp tests/data/dcos.toml $DCOS_CONFIG
if [ -f "$BASEDIR/env/bin/activate" ]; then
	source $BASEDIR/env/bin/activate
else
	$BASEDIR/env/Scripts/activate
fi
if [ -n "$single_test" ]; then
	py.test "tests/integration/test_cli.py::$single_test"
else
	py.test tests/integration
fi
deactivate
