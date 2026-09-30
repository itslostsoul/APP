#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -rf out && mkdir out
javac --release 17 -encoding UTF-8 -d out src/*.java
printf 'Main-Class: SandboxGUI\n' > out/manifest.txt
jar cfm AMAS.jar out/manifest.txt -C out .
echo "Built AMAS.jar"
