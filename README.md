# blueborne

Some PoC scripts for the Blueborne vulnerabilities on Android

## Contents

- crash_service.py: Crashes the remote Bluetooth service using CVE-2017-0781
- leak_memory.py: Leaks memory from the remote device using CVE-2017-0785
- rce: Complex Remote Code Execution to open a reverse shell with the privileges of the Bluetooth service using both CVE-2017-0781 and CVE-2017-0785
