#!/bin/bash -e

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/.."

cd $BASEDIR

PATH=$(pwd)/dist:$PATH
[ -n "$DCOS_CONFIG" ] && cp tests/data/dcos.toml $DCOS_CONFIG
if [ -f "$BASEDIR/env/bin/activate" ]; then
	source $BASEDIR/env/bin/activate
else
	$BASEDIR/env/Scripts/activate
fi
py.test tests/integration
deactivate
