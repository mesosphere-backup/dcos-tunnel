#!/bin/bash -e

test_input="$1"

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/.."

cd $BASEDIR

PATH=$(pwd)/dist:$PATH
source $BASEDIR/env/bin/activate
if [ -n "$test_input" ]; then
	py.test -s -vv "$test_input"
else
	py.test -vv tests/integration
fi
deactivate
