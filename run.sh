#!/usr/bin/env bash
cd "$(dirname "$0")"
[ -f AMAS.jar ] || ./build.sh
exec java -jar AMAS.jar "$@"
