# Incident report — base-dc-memory.img

**Generated on:** 2026-06-11 05:44 UTC  
**Target:** Windows Server 2016 domain controller (SRL-2018 scenario)  
**Method:** Investigation agent via Splunk MCP Server (custom forensic tools)  
**MCP tools used:** forensics_attack_timeline, forensics_find_attack_techniques, forensics_investigate_process, forensics_triage_summary

## Verdict: **COMPROMISED**

The agent identified **4 critical detection(s)** and **7 high detection(s)** on the domain controller. The attack chain corresponds to an Active Directory credential exfiltration.

## Detected kill-chain (MITRE ATT&CK)

| Severity | Rule | MITRE | Description |
|---|---|---|---|
| critical | `LOLBin_NTDS_Access` | T1003.003, T1074 | LOLBin tools accessing Active Directory database |
| critical | `Credential_Dumping_Framework` | T1003.001 | Credential dumping framework signatures (mimikatz, etc.) |
| critical | `NTDS_Staging_Path` | T1074.001 | NTDS.dit staged in temp directory |
| critical | `NTDS_Extraction_ntdsutil` | T1003.003 | NTDS.dit extraction via ntdsutil IFM |
| high | `Schtasks_Persistence_Creation` | T1053.005 | Scheduled task creation for persistence |
| high | `LOLBin_Download_Tools` | T1105 | Living-off-the-land download (bitsadmin, certutil, curl) |
| high | `PsExec_Remote_Execution` | T1021.002 | PsExec-style remote execution |
| high | `WMI_Remote_Execution` | T1021.006, T1047 | WMI remote execution for lateral movement |
| high | `PowerShell_Remote_Download` | T1105 | PowerShell downloading remote payload |
| high | `PowerShell_Obfuscated_Execution` | T1059.001, T1027 | PowerShell with obfuscation/encoding |
| high | `Shadow_Copy_Credential_Theft` | T1003, T1006 | Credential extraction via VSS shadow copies |
| medium | `PowerShell_Remoting_Session` | T1021.006 | PowerShell Remoting (WinRM/WS-Man) session |
| medium | `Recycle_Bin_Antiforensic` | T1070 | Move to Recycle Bin for anti-forensic cleanup |
| informational | `SRL2018_Scenario_Markers` |  | Specific markers for SRL-2018 scenario (shieldbase.lan domain) |
| informational | `Defender_Blocked_Execution` |  | Windows Defender blocked malicious execution |

## Suspicious processes identified

| Process | PID | PPID | Creation | Session |
|---|---|---|---|---|
| powershell.exe | 5612 | 4932 | 2018-08-16T22:10:54+00:00 | 1 |
| cmd.exe | 4508 | 4300 | 2018-08-16T21:37:38+00:00 | 1 |
| cmd.exe | 2284 | 4300 | 2018-08-17T00:59:00+00:00 | 1 |
| cmd.exe | 5068 | 4840 | 2018-09-01T17:18:03+00:00 | 0 |
| cmd.exe | 3400 | 3564 | 2018-09-01T17:43:10+00:00 | 0 |
| cmd.exe | 6648 | 3564 | 2018-09-01T17:43:10+00:00 | 0 |
| cmd.exe | 4588 | 908 | 2018-09-01T17:48:11+00:00 | 0 |
| cmd.exe | 6640 | 8988 | 2018-09-01T21:19:14+00:00 | 0 |
| cmd.exe | 6604 | 4444 | 2018-09-02T00:30:13+00:00 | 0 |
| cmd.exe | 5948 | 7124 | 2018-09-02T01:15:25+00:00 | 0 |
| cmd.exe | 7204 | 7124 | 2018-09-02T01:15:25+00:00 | 0 |
| cmd.exe | 8872 | 8664 | 2018-09-03T18:11:30+00:00 | 0 |
| cmd.exe | 4960 | 6584 | 2018-09-03T21:22:22+00:00 | 0 |
| cmd.exe | 8792 | 6584 | 2018-09-03T21:22:22+00:00 | 0 |
| cmd.exe | 7732 | 7696 | 2018-09-04T14:42:09+00:00 | 0 |
| cmd.exe | 6156 | 940 | 2018-09-04T15:07:15+00:00 | 0 |
| cmd.exe | 4648 | 1036 | 2018-09-06T17:47:38+00:00 | 0 |
| cmd.exe | 1036 | 908 | 2018-09-06T17:47:38+00:00 | 0 |
| cmd.exe | 2308 | 1036 | 2018-09-06T17:47:39+00:00 | 0 |
| cmd.exe | 6940 | 1036 | 2018-09-06T17:47:39+00:00 | 0 |
| cmd.exe | 3380 | 908 | 2018-09-06T18:17:46+00:00 | 0 |
| cmd.exe | 6572 | 3380 | 2018-09-06T18:17:46+00:00 | 0 |
| cmd.exe | 8220 | 6628 | 2018-09-06T22:53:58+00:00 | 0 |
| cmd.exe | 7260 | 6628 | 2018-09-06T22:53:58+00:00 | 0 |
| cmd.exe | 6628 | 908 | 2018-09-06T22:53:58+00:00 | 0 |
| cmd.exe | 9012 | 6628 | 2018-09-06T22:53:58+00:00 | 0 |

## Recommendations

1. **Isolate** the domain controller from the network immediately.
2. **Reset** krbtgt (twice) and all privileged accounts — NTDS.dit is compromised.
3. **Hunt** for lateral movement via PsExec/WMI to the other hosts.
4. **Preserve** the memory image and the logs as evidence.

---
*Report generated automatically by the forensic agent — Splunk Agentic Ops Hackathon.*