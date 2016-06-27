#!/bin/bash -e

BASEDIR=`dirname $0`/..

cd $BASEDIR

PATH=$(pwd)/dist:$PATH
$BASEDIR/env/bin/tox
