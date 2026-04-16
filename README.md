# RoboVault

FANUC robot controller backup tool. Backs up R-30iA/iB/iB+ controllers
over FTP with parallel downloads, scheduling, retention, and diff.

See SECURITY.md for the threat model and ASVS control mapping.

## Build

    pyinstaller --clean --onedir --windowed --name RoboVault robovault_portable.py