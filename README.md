Tool Updates

New files in the repository:

ToolUpdates.pdf – PDF of this file
Pdwc_v2.py – version two of workstation checker
Winrm_teardown.ps1 – PowerShell that reverses changes made in wrm_setup.ps1

YouTube video link
Link to parallel processing speed video - https://youtu.be/-fe46QZfotM

Summary of updates
Thank you to my reviewers for providing some great feedback on Tool #2.  My suggestions to improve the tool included the following:
•	Add more checks to the tool besides the current three.
•	Have the tool process requests in parallel to speed the process.
•	Include a script that reverses the changes that wnrm_setup.ps1 makes to the Windows client.

Changes made
I added another check to the tool that scans the Windows computer for open ports.  The tool has ALLOWED_PORTS and FORBIDDEN_PORTS that can be customized to the security policy.  Default allowed ports include 135, 139 for RPC and NetBIOS Session Service as well as 5985 and 5986 for the tool to work.  Forbidden ports include 23 (telnet), 3389(rdp), 5900 (VNC), 4444 (Metasploit), 1433(sql server), and 3306 (mysql).  The tool warns on unexpected ports that should be checked and will fail on any forbidden ports found open.
I added parallel processing capabilities to the tool to improve its speed.  The tool now runs all checks simultaneously on the workstation as well as running all workstations simultaneously.  These two additions really made the tools faster and more likely to be used in a corporate environment with many workstations.  This check has a MAX_WORKERS that can be configured to limit the number of checks(threads) that can run simultaneously.  After adding the fourth check and another workstation it scans all 4 workstations with 4 checks in about 10 seconds.  The old version had 3 checks and 3 workstations and took about 20 seconds.  
I also added a PowerShell script that reverses the changes that wnrm_setup.ps1 makes to the workstation.  The script removes the following: 
•	removes the firewall rule
•	removes the self-signed  WinRM certificates
•	resets TrustedHosts back to empty
•	disables PowerShell Remoting
•	removes the HTTP listener
This script will reset the workstation configuration back to where it was before winrm_setup was run.
I implemented all the feedback I received.

Lessons Learned
I learned a great deal from creating this tool.  I continue to improve my understanding of python.  I created this tool so it was in a modular layout, and checks could be added in a systematic way.  I am learning what it takes to develop a small piece of software and the relationships between different portions of code and how they interact.
I am learning a great deal from my peers on not only my own code but figuring out what they have created and what I need to do to make it run as designed.

Future work if I was to continue this project
If I were to continue this project, I would like to have the three functions integrated into a seamless system.  I would take the setup script, the main workstation checker program, and the teardown script and integrate them into one seamless package.


















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
