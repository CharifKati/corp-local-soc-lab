# Active Directory Threat Detection Lab

Built a 3-VM home lab from scratch, simulated 5 real-world Active Directory attacks from a Kali attacker machine, and wrote Splunk detection rules and incident reports for each one. Every rule was validated against actual event data - not copied from documentation.

During the lab I found that `src_ip` does not exist as a field in raw Windows Security Event logs, despite appearing in most online detection guides. Field names vary by EventCode: `Source_Network_Address` for 4624/4625, `Client_Address` for 4769. Every rule here was verified with `| fieldsummary` first.

**Stack:** Windows Server 2022 - Kali Linux - Ubuntu - Splunk 10.2 - Sysmon  
**Domain:** corp.local - **Date:** February 2026

---

## Attacks Simulated

| # | Attack | MITRE ID | Severity | Result |
|---|--------|----------|----------|--------|
| 01 | Active Directory Enumeration | T1087 / T1018 | Medium | All domain accounts mapped |
| 02 | Password Spray | T1110.003 | High | amartin compromised |
| 03 | Kerberoasting | T1558.003 | High | svc_sql hash cracked offline |
| 04 | Backdoor Admin Account | T1136.001 | Critical | Persistent Domain Admin established |
| 05 | DCSync - Full Hash Dump | T1003.006 | Critical | Every credential in the domain dumped |

---

## Things That Did Not Work As Expected

**EventCode 4662 does not fire by default.**
Two attacks depend on this event - AD Enumeration and DCSync. It only logs if `Audit Directory Service Access` is explicitly enabled via `auditpol`. Off by default on Windows Server 2022. I found out because Splunk kept returning nothing even though the attacks were running fine. A SOC without this enabled has a complete blind spot for DCSync and would never know.

**EventCode 4728 did not fire during the backdoor account attack.**
The group membership add to Domain Admins should have generated this event but did not in this environment. The detection rule was adjusted to filter on the account name pattern via EventCode 4720 instead, which still caught the attack. It highlights that a rule correlating 4720 and 4728 can miss this in certain configurations.

**Kerberoasting leaves almost no trace.**
The only detectable moment is the initial TGS request. After that, cracking happens entirely offline with zero further DC interaction. If the service account enforces AES, the hash is not crackable with standard tools. svc_sql was using RC4, which is why it worked.

---

## Detection Rules

### 01 - AD Enumeration (T1087)
```spl
index=main EventCode=4662
| bin _time span=5m
| stats count by _time, Account_Name
| where count > 20
| sort -count
```
Triggers on high-volume LDAP object access. Normal users never hit this threshold.  
**Blind spot:** CrackMapExec uses SMB not LDAP, generates 4624 instead of 4662.

---

### 02 - Password Spray (T1110.003)
```spl
index=main EventCode=4625
| bin _time span=5m
| stats dc(Account_Name) as unique_accounts, count by _time, Source_Network_Address
| where unique_accounts > 3
| sort -count
```
`dc()` counts distinct usernames. One IP failing against 4+ accounts in 5 minutes is a spray, not a typo.  
**Blind spot:** A spray with 30+ minute gaps between rounds evades the 5-minute window.

---

### 03 - Kerberoasting (T1558.003)
```spl
index=main EventCode=4769 Ticket_Encryption_Type=0x17
| where Service_Name!="krbtgt" AND NOT like(Service_Name, "%$")
| stats count by Client_Address, Service_Name
| where count > 2
| sort -count
```
RC4 (0x17) TGS requests are the Kerberoasting signature. Modern AD uses AES (0x12) by default.  
**Blind spot:** A single targeted request does not meet the count threshold.

---

### 04 - Backdoor Account (T1136.001)
```spl
index=main EventCode=4720
| where Account_Name="support_user" OR Account_Name LIKE "%support%"
| table _time, SubjectUserName, Account_Name
```
Catches account creation by name pattern. Should correlate with EventCode 4728 in production.  
**Blind spot:** Fires on legitimate onboarding without that correlation.

---

### 05 - DCSync (T1003.006)
```spl
index=main EventCode=4662
| search Message="*{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}*"
    OR Message="*{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}*"
| where NOT like(SubjectUserName, "%$")
| table _time, SubjectUserName, Message
```
Searches for the DS-Replication-Get-Changes GUIDs DCSync requires. NOT like removes legitimate DC computer accounts ending in `$`. Any human account hitting these GUIDs is an immediate critical alert.  
**Blind spot:** Requires Audit Directory Service Access enabled - see note above.

---

## Repository Structure

```
corp-local-soc-lab/
|-- README.md
|-- detections/
|   |-- AD-Enumeration-Detected-T1087.spl
|   |-- Password-Spray-Detected-T1110-003.spl
|   |-- Kerberoasting-Attempt-Detected-T1558-003.spl
|   |-- Backdoor-Account-Created-T1136-001.spl
|   |-- DCSync-Attack-Detected-T1003-006.spl
|-- incident-reports/
|   |-- IR-001-AD-Enumeration-T1087.pdf
|   |-- IR-002-Password-Spray-T1110.pdf
|   |-- IR-003-Kerberoasting-T1558.pdf
|   |-- IR-004-Backdoor-Account-T1136.pdf
|   |-- IR-005-DCSync-T1003.pdf
|-- lab-setup/
    |-- SOC_Lab_Report.pdf
```

---

## Lab Infrastructure

| VM | OS | IP | Role |
|----|----|----|------|
| DC01 | Windows Server 2022 | 192.168.233.133 | Domain Controller (corp.local) |
| splunk-soc | Ubuntu Server | 192.168.233.129 | Splunk SIEM |
| kali | Kali Linux | 192.168.233.128 | Attacker |

Logs shipped via Splunk Universal Forwarder over TCP 9997. Sysmon installed on DC01 for extended event coverage.

---

## References

- [MITRE ATT&CK - Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/)
- [Windows Security Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
