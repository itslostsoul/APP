@echo off
cd /d "%~dp0"
if not exist out\SandboxGUI.class call build.bat
if not exist out\SandboxGUI.class (
  echo Build failed. See the messages above.
  pause
  exit /b 1
)
java -cp out SandboxGUI %*
if errorlevel 1 pause
