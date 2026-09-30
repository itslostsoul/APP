@echo off
cd /d "%~dp0"
if exist out rmdir /s /q out
mkdir out
javac --release 17 -encoding UTF-8 -d out src\*.java
if errorlevel 1 ( echo Compile failed. & pause & exit /b 1 )
echo Built into the out folder.
