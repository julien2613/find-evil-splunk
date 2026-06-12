// ==========================================================================
// APT Detection Rules — calibrated for SRL-2018 Compromised Enterprise Network
// Usage: yara-x scan apt_detection_rules.yar base-dc-memory.img
// ==========================================================================

// --- CREDENTIAL ACCESS ---

rule NTDS_Extraction_ntdsutil {
    meta:
        description = "NTDS.dit extraction via ntdsutil IFM"
        severity = "critical"
        mitre = "T1003.003"
        author = "hackathon"
    strings:
        $ntdsutil = "ntdsutil" nocase
        $ifm = "ifm" nocase
        $create_full = "create full" nocase
        $ntds_dit = "ntds.dit" nocase
        $ac_ntds = "ac i ntds" nocase
    condition:
        // Au moins 3 indicateurs + ntds.dit
        $ntds_dit and 2 of ($ntdsutil, $ifm, $create_full, $ac_ntds)
}

rule NTDS_Staging_Path {
    meta:
        description = "NTDS.dit staged in temp directory"
        severity = "critical"
        mitre = "T1074.001"
    strings:
        $path1 = "C:\\Windows\\temp\\perfmon\\Active Directory\\ntds.dit" nocase
        $path2 = "c:\\windows\\temp\\perfmon" nocase
        $suspicious_dirs = /C:\\Windows\\temp\\[a-z]+\\Active Directory/ nocase
    condition:
        any of them
}

rule Shadow_Copy_Credential_Theft {
    meta:
        description = "Credential extraction via VSS shadow copies"
        severity = "high"
        mitre = "T1003, T1006"
    strings:
        $vss1 = "vssadmin" nocase
        $vss2 = "create shadow" nocase
        $vss3 = "HarddiskVolumeShadowCopy" nocase
        $sam_path = "Windows\\System32\\config\\SAM" nocase
        $system_path = "Windows\\System32\\config\\SYSTEM" nocase
        $gmt_snapshot = /@GMT-\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}/
        $globalroot = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy"
    condition:
        // VSS + credential file = attaque confirmée
        (1 of ($vss*) and 1 of ($sam_path, $system_path))
        or $gmt_snapshot
        or $globalroot
}

rule Credential_Dumping_Framework {
    meta:
        description = "Credential dumping framework signatures (mimikatz, etc.)"
        severity = "critical"
        mitre = "T1003.001"
    strings:
        $mk1 = "sekurlsa::logonpasswords" nocase
        $mk2 = "lsadump::sam" nocase
        $mk3 = "lsadump::secrets" nocase
        $mk4 = "privilege::debug" nocase
        $mk5 = "kerberos::golden" nocase
        $hd1 = "Get-PassHashes" nocase
        $hd2 = "Invoke-PassTheTicket" nocase
        $hd3 = "secretsdump" nocase
    condition:
        2 of them  // Multiple indicateurs pour éviter false positives AV
}

// --- EXECUTION / OBFUSCATION ---

rule PowerShell_Obfuscated_Execution {
    meta:
        description = "PowerShell with obfuscation/encoding"
        severity = "high"
        mitre = "T1059.001, T1027"
    strings:
        $enc1 = "-enc " nocase
        $enc2 = "-encodedcommand" nocase
        $enc3 = "-e " nocase fullword
        $fb64 = "frombase64string" nocase
        $iex1 = "iex (" nocase
        $iex2 = "invoke-expression" nocase
        $iex3 = "IEX((" nocase
        $hidden = "-windowstyle hidden" nocase
        $bypass = "-exec bypass" nocase
        $nop = "-nop " nocase
        $noprofile = "-noprofile" nocase
    condition:
        // Combinaison de 3+ flags d'obfuscation
        3 of them
}

rule PowerShell_Remote_Download {
    meta:
        description = "PowerShell downloading remote payload"
        severity = "high"
        mitre = "T1105"
    strings:
        $wc = "Net.WebClient" nocase
        $dl_string = "DownloadString" nocase
        $dl_file = "DownloadFile" nocase
        $new_obj = "New-Object" nocase
        $invoke_wr = "Invoke-WebRequest" nocase
        $invoke_rm = "Invoke-RestMethod" nocase
    condition:
        (1 of ($dl_string, $dl_file) and ($wc or $new_obj))
        or 1 of ($invoke_wr, $invoke_rm)
}

// --- DEFENSE EVASION ---

rule Defender_Blocked_Execution {
    meta:
        description = "Windows Defender blocked malicious execution"
        severity = "informational"
        note = "Signal that attacker attempted malware but was blocked"
    strings:
        $msg = "file contains a virus or potentially unwanted software" nocase
    condition:
        $msg
}

rule Recycle_Bin_Antiforensic {
    meta:
        description = "Move to Recycle Bin for anti-forensic cleanup"
        severity = "medium"
        mitre = "T1070"
    strings:
        $rb1 = "$Recycle.Bin" nocase
        $move = "Move-Item" nocase
        $param = "ParameterBinding(Move-Item)"
    condition:
        $rb1 and ($move or $param)
}

// --- LATERAL MOVEMENT ---

rule WMI_Remote_Execution {
    meta:
        description = "WMI remote execution for lateral movement"
        severity = "high"
        mitre = "T1021.006, T1047"
    strings:
        $wmic = "wmic" nocase
        $node = "/node:" nocase
        $process_call = "process call create" nocase
        $invoke_wmi = "Invoke-WmiMethod" nocase
        $shadowcopy = "shadowcopy" nocase
    condition:
        ($wmic and $node) or ($invoke_wmi) or ($wmic and $shadowcopy) or ($wmic and $process_call)
}

rule PsExec_Remote_Execution {
    meta:
        description = "PsExec-style remote execution"
        severity = "high"
        mitre = "T1021.002"
    strings:
        $psexec = "psexec" nocase
        $temp_psexec = "\\temp\\psexec" nocase
        $svcctl = "svcctl" nocase
        $admin_share = /\\\\[a-z0-9\-]+\\admin\$/ nocase
    condition:
        any of them
}

rule PowerShell_Remoting_Session {
    meta:
        description = "PowerShell Remoting (WinRM/WS-Man) session"
        severity = "medium"
        mitre = "T1021.006"
    strings:
        $ws_man = "schemas.microsoft.com/wbem/wsman" nocase
        $runspace_pool = "RunspacePool" nocase
        $enter_pssession = "enter-pssession" nocase
        $invoke_command = "invoke-command" nocase
        $new_pssession = "new-pssession" nocase
    condition:
        3 of them
}

// --- LOLBINS ---

rule LOLBin_Download_Tools {
    meta:
        description = "Living-off-the-land download (bitsadmin, certutil, curl)"
        severity = "high"
        mitre = "T1105"
    strings:
        $bits_transfer = /bitsadmin\s+\/transfer/ nocase
        $certutil_url = /certutil\s+-urlcache/ nocase
        $certutil_decode = /certutil\s+-decode/ nocase
    condition:
        any of them
}

rule LOLBin_NTDS_Access {
    meta:
        description = "LOLBin tools accessing Active Directory database"
        severity = "critical"
        mitre = "T1003.003, T1074"
    strings:
        $ntdsutil = "ntdsutil.exe" nocase
        $esentutl = "esentutl" nocase
        $reg_save = "reg save" nocase
        $ntds_dit = "ntds.dit" nocase
    condition:
        $ntds_dit and 1 of ($ntdsutil, $esentutl, $reg_save)
}

// --- SCHEDULED TASKS (PERSISTENCE) ---

rule Schtasks_Persistence_Creation {
    meta:
        description = "Scheduled task creation for persistence"
        severity = "high"
        mitre = "T1053.005"
    strings:
        $create = /schtasks\s+\/create/ nocase
        $run_as = /\/ru\s+system/i
        $onstart = "/sc onstart" nocase
        $onlogon = "/sc onlogon" nocase
        $minute = "/sc minute" nocase
    condition:
        $create and 1 of ($run_as, $onstart, $onlogon, $minute)
}

// --- SPECIFIC SRL-2018 IOC ---

rule SRL2018_Scenario_Markers {
    meta:
        description = "Specific markers for SRL-2018 scenario (shieldbase.lan domain)"
        severity = "informational"
    strings:
        $domain = "shieldbase.lan" nocase
        $dc = "BASE-DC" nocase
        $spsql = "shieldbase\\spsql" nocase
        $admin_user = "rsydow-a" nocase
        $fresponse = "F-Response Subject" nocase
    condition:
        any of them
}
