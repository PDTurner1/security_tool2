# security_tool2

Pre-Deployment Workstation Check (PDWC) 1.0 is a tool written in Python to check specific security settings as a pre-deployment check on Windows workstations.  It utilizes python3, pywinRM, and WinRM (Windows Remote Management) to connect to workstations to find the status of various services. The system has three warning levels depending on the severity of what it finds.  This tool can be used as a lightweight checker to be sure Windows workstations are in compliance with build policies.

PDWC checks:
The status of Windows Defender and Antivirus.  The system will detect whether windows defender and antivirus is enabled. It will report if the signature age is out of date and if the quick scan feature has not been run recently.

The status of Windows firewall is checked to be sure it is enabled on Domain, Public, and Private.  It will report which firewalls are disabled, if any.

The status of bitlocker is checked to be sure all drives have been encrypted.  The tool will flag any drives that are not encrypted.  The tool will return a percentage of encryption if the encryption is in process.

To run on Ubuntu:
1.	Sudo apt update.
2.	Sudo apt install python3-pip
3.	Sudo pip install pywinrm –break-system-packages

To run against a Windows client run the following commands on the client in Powershell by an Administrator:
1.	Set-ExecutionPolicy unrestricted
2.	./winrm_setup.ps1 (included in github)
3.	Enable-PSRemoting – Force

Once these items are complete you can scan a client using the following:

python3 pdwc.py --host <ip_address> --user <username> --json-dir <./<directory>

Example: python3 pdwc.py --host 192.168.12.12 --user testuser --json-dir ./jsonlogs

To scan several IP addresses at a time use the --hosts-file option:

python3 pdwc.py --host-file hosts.txt --user Administrator --json-dir ./jsonlogs

Where hosts.txt contains:
192.168.12.100
192.168.12.101
192.168.12.102

Please read PDWC documentation for full details.  

Please let me know if you have any questions or concerns.

Thank you.

Patrick
