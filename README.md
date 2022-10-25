# security-compliance-grader
Made to help high school class, use as you wish 

Run as admin in powershell prompt with ``Set-ExecutionPolicy Bypass -Scope Process -Force; .\verification.ps1`` or ``Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/HopeAnnihilator/security-compliance-grader/main/verification.ps1'))`` if you wish to run without saving (bypasses checksum)

For basic obscurity the printed total and checksum are base64 encoded 

![alt text](https://github.com/HopeAnnihilator/security-compliance-grader/blob/main/demo.png?raw=true)
