#  Checklist with Contextual Insights

## User Accounts and Privilege Investigation

### View Local User Accounts

```powershell
lusrmgr.msc          # GUI - View local users and groups
net user             # CMD - List local users
Get-LocalUser        # PowerShell - More detailed local user info
```

> **Why:** Identify suspicious or unexpected accounts, especially recently created ones.

### View Local Administrators

```powershell
net localgroup administrators
Get-LocalGroupMember Administrators
```

> **Why:** Check if any unauthorized users have admin access.

---

## Process Analysis

```powershell
taskmgr.exe                             # GUI - Quick visual of running processes
tasklist                                 # CMD - All processes with PIDs
Get-Process                              # PowerShell - Similar to tasklist
wmic process get name,parentprocessid,processid
wmic process where 'ProcessID=PID' get CommandLine
```

> **Why:** Look for suspicious or hidden processes (e.g., powershell.exe or rundll32.exe with long command lines).

---

## Service Inspection

```powershell
services.msc                            # GUI - Manage services
net start                               # CMD - Lists running services
sc query | more                         # CMD - Scrollable service list
tasklist /svc                           # CMD - Which service runs under which process
Get-Service | Format-Table -AutoSize    # PowerShell - Detailed view
```

> **Why:** Look for malicious or unauthorized services, persistence mechanisms.

---

## Scheduled Task Inspection

```powershell
schtasks                                # CMD - List all tasks
Get-ScheduledTask | Format-Table -AutoSize
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User | Format-List
```

> **Why:** Malware often uses scheduled tasks for persistence.

#### GUI: Task Scheduler

```
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools
```

#### Enable/Disable Scheduled Tasks

```powershell
Disable-ScheduledTask -TaskName "Name"
Enable-ScheduledTask -TaskName "Name"
```

---

## Registry Run Keys

```powershell
regedit                                              # GUI registry viewer
reg query HKLM\...\Run                              # CMD - System-wide autoruns
reg query HKCU\...\Run                              # CMD - User-specific autoruns
```

```powershell
# PowerShell equivalent:
cd HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
Get-ChildItem | Where-Object {$_.Name -like "*Run*"}
```

> **Why:** Registry Run keys are a common persistence location.

---

## Network Connections & Lateral Movement

### Active Connections

```powershell
netstat -anob
Get-NetTCPConnection | Format-Table -AutoSize
```

> **Why:** Detect connections to C2 servers, lateral movement, or suspicious ports.

### SMB Shares and Sessions

```powershell
net view \\IP
net use
net session
Get-SMBShare
Get-SmbMapping
```

> **Why:** Check if the system is accessing or hosting shares unexpectedly.

---

## File System Hunting (Local Profile)

```powershell
cd %HOMEPATH%
forfiles /D -10 /S /M *.exe /C "cmd /c echo @path"
```

```powershell
# PowerShell: hunt for recent .exe files
Get-ChildItem -Recurse -Force -Include *.exe | Sort-Object Name | Format-Table Name, Fullname -AutoSize
# Created in last 24 hrs
Get-ChildItem -Recurse -Force -Include *.exe | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)}
```

> **Why:** Check for dropped or newly installed executables.

---

## Windows Firewall Inspection

```powershell
netsh firewall show config
netsh advfirewall show currentprofile
Get-NetFirewallRule | Where Enabled -eq $true | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
```

> **Why:** Ensure firewall is on and rules haven’t been tampered with.

---

## Log and Event Inspection

```powershell
eventvwr.msc
Get-EventLog -List
Get-EventLog System -After (Get-Date).AddHours(-2) | Format-Table -AutoSize
```

> **Why:** Look for recent crash logs, login attempts, service errors, and suspicious system behavior.

### Search Specific Messages

```powershell
Get-EventLog System | Where-Object {$_.Message -like "*Server*"}
```

### System Stability

```powershell
perfmon /rel         # GUI - Reliability Monitor
```

> **Why:** Investigate system crashes or sudden behavior changes.

---

Let me know if you'd like this exported as a Markdown `.md` checklist, converted to Obsidian note, or formatted for incident response playbooks.
