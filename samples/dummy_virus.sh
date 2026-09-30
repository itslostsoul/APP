#!/bin/sh
echo "[MALWARE] Execution started..."
echo "[MALWARE] Attempting to create hidden persistence directory..."
mkdir -p /sandbox/.hidden_payload

echo "[MALWARE] Searching for sensitive files..."
ls -la /etc/passwd

echo "[MALWARE] Attempting to contact external Command & Control server..."
ping -c 2 8.8.8.8

echo "[MALWARE] Payload deployed. Exiting with error code to simulate crash."
exit 1