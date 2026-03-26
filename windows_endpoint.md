| tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
  from datamodel=Endpoint.Services
  where nodename=Services (
    Services.action=created OR Services.action=installed OR Services.status=created
  )
  by Services.dest Services.user Services.service_name Services.service_path Services.service_type Services.process Services.process_path
| rename Services.* as *
| eval suspicious_path=if(
    match(lower(service_path), "\\\\users\\\\|\\\\programdata\\\\|\\\\temp\\\\|\\\\appdata\\\\|\\\\perflogs\\\\|\\\\recycle\\.bin\\\\")
    OR match(lower(service_path), "^.:\\\\windows\\\\temp\\\\")
    OR match(lower(service_path), "^.:\\\\temp\\\\"),
    1, 0
  )
| eval encoded_name=if(
    match(service_name, "^[A-Za-z0-9+/=]{12,}$")
    OR match(service_name, "^[a-fA-F0-9]{16,}$")
    OR match(service_name, "^[A-Za-z]{1}[0-9A-Za-z]{10,}$"),
    1, 0
  )
| eval psexec_flag=if(
    like(lower(service_name), "psexesvc%")
    OR like(lower(service_path), "%psexesvc%")
    OR like(lower(process), "%psexec%"),
    1, 0
  )
| where suspicious_path=1 OR encoded_name=1 OR psexec_flag=1
| eval alert_name=case(
    psexec_flag=1, "New Service Installation - PsExec Service Detected",
    suspicious_path=1 AND encoded_name=1, "New Service Installation - Suspicious Path and Encoded Service Name",
    suspicious_path=1, "New Service Installation - Suspicious Service Path",
    encoded_name=1, "New Service Installation - Suspicious Encoded Service Name",
    true(), "New Service Installation - Suspicious Service Creation"
  )
| eval severity=case(
    psexec_flag=1, "High",
    suspicious_path=1 AND encoded_name=1, "High",
    suspicious_path=1 OR encoded_name=1, "Medium",
    true(), "Low"
  )
| eval mitre_tactic="Persistence"
| eval mitre_technique="T1543.003 - Create or Modify System Process: Windows Service"
| eval service_file_name=service_path
| rename _time as trigger_time
| table trigger_time alert_name severity mitre_tactic mitre_technique dest user process process_path service_name service_file_name service_type count

----

| multisearch

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Endpoint.Processes
      where nodename=Processes (
        Processes.process_name=* OR Processes.process=*
      )
      by Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process Processes.target_process
      | rename Processes.* as *
      | where like(lower(target_process), "%lsass.exe%")
      | eval technique="LSASS Access"
      | eval target="lsass.exe"
      | eval base_severity="High"
    ]

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Endpoint.Processes
      where nodename=Processes
      by Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process
      | rename Processes.* as *
      | eval proc_l=lower(coalesce(process,"")." ".coalesce(process_path,""))
      | where like(proc_l, "%mimikatz%")
          OR like(proc_l, "%sekurlsa%")
          OR like(proc_l, "%procdump%")
          OR like(proc_l, "%comsvcs.dll%")
          OR like(proc_l, "%rundll32%comsvcs.dll%")
      | eval technique=case(
          like(proc_l, "%mimikatz%") OR like(proc_l, "%sekurlsa%"), "Mimikatz Execution",
          like(proc_l, "%procdump%"), "Procdump Usage",
          like(proc_l, "%comsvcs.dll%"), "comsvcs.dll Dump Method",
          true(), "Credential Dumping Tool Use"
        )
      | eval target=case(
          like(proc_l, "%lsass%"), "lsass.exe",
          like(proc_l, "%comsvcs.dll%"), "lsass.exe",
          true(), "credential material"
        )
      | eval base_severity=case(
          like(proc_l, "%mimikatz%"), "Critical",
          like(proc_l, "%sekurlsa%"), "Critical",
          true(), "High"
        )
    ]

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Registry
      where (
        Registry.registry_path="*\\SAM\\SAM*"
        OR Registry.registry_path="*\\SECURITY*"
        OR Registry.registry_path="*\\SYSTEM*"
      )
      by Registry.dest Registry.user Registry.process Registry.registry_path
      | rename Registry.* as *
      | eval technique="SAM/SECURITY/SYSTEM Hive Access"
      | eval target=registry_path
      | eval process_path=process
      | eval base_severity="High"
    ]

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Endpoint.Filesystem
      where nodename=Filesystem (
        Filesystem.file_path="*\\ntds.dit"
        OR Filesystem.file_name="ntds.dit"
      )
      by Filesystem.dest Filesystem.user Filesystem.process Filesystem.file_name Filesystem.file_path
      | rename Filesystem.* as *
      | eval technique="NTDS.dit Extraction Attempt"
      | eval target=file_path
      | eval process_path=process
      | eval base_severity="Critical"
    ]

| eval alert_name="Credential Dumping Indicator - ".technique
| eval severity=base_severity
| eval mitre_tactic="Credential Access"
| eval mitre_technique=case(
    technique="LSASS Access", "T1003.001 - OS Credential Dumping: LSASS Memory",
    technique="Mimikatz Execution", "T1003 - OS Credential Dumping",
    technique="Procdump Usage", "T1003.001 - OS Credential Dumping: LSASS Memory",
    technique="comsvcs.dll Dump Method", "T1003.001 - OS Credential Dumping: LSASS Memory",
    technique="SAM/SECURITY/SYSTEM Hive Access", "T1003.002 - Security Account Manager",
    technique="NTDS.dit Extraction Attempt", "T1003.003 - NTDS",
    true(), "T1003 - OS Credential Dumping"
  )
| rename _time as trigger_time
| table trigger_time alert_name severity mitre_tactic mitre_technique dest user process process_path technique target count

----

| multisearch

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Change
      where (
        Change.result_id=4720 OR Change.signature_id=4720 OR Change.action=created
      )
      by Change.dest Change.user Change.src Change.object Change.object_category Change.result_id Change.command
      | rename Change.* as *
      | eval technique="Local Account Created"
      | eval target=coalesce(object, command, "new local account")
      | eval base_severity="Medium"
    ]

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Change
      where (
        Change.result_id=4728 OR Change.result_id=4732 OR Change.signature_id=4728 OR Change.signature_id=4732
      )
      by Change.dest Change.user Change.src Change.object Change.object_category Change.result_id Change.command
      | rename Change.* as *
      | eval technique="Account Added to Privileged Group"
      | eval target=coalesce(object, command, "privileged group membership")
      | eval base_severity="High"
    ]

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Change
      where (
        Change.result_id=4722 OR Change.signature_id=4722
      )
      by Change.dest Change.user Change.src Change.object Change.object_category Change.result_id Change.command
      | rename Change.* as *
      | eval technique="Disabled Account Enabled"
      | eval target=coalesce(object, command, "enabled account")
      | eval base_severity="Medium"
    ]

    [ | tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
      from datamodel=Change
      where (
        Change.object="*SIDHistory*" OR Change.command="*SIDHistory*" OR Change.object_attrs="*SIDHistory*"
      )
      by Change.dest Change.user Change.src Change.object Change.object_category Change.command
      | rename Change.* as *
      | eval technique="SID History Injection Indicator"
      | eval target=coalesce(object, command, "SIDHistory")
      | eval base_severity="Critical"
    ]

| eval alert_name="Anomalous Account Activity - ".technique
| eval severity=base_severity
| eval mitre_tactic=case(
    technique="Local Account Created", "Persistence",
    technique="Account Added to Privileged Group", "Privilege Escalation",
    technique="Disabled Account Enabled", "Persistence",
    technique="SID History Injection Indicator", "Privilege Escalation",
    true(), "Persistence"
  )
| eval mitre_technique=case(
    technique="Local Account Created", "T1136.001 - Create Account: Local Account",
    technique="Account Added to Privileged Group", "T1098 - Account Manipulation",
    technique="Disabled Account Enabled", "T1098 - Account Manipulation",
    technique="SID History Injection Indicator", "T1134.005 - Access Token Manipulation: SID-History Injection",
    true(), "T1098 - Account Manipulation"
  )
| rename _time as trigger_time
| table trigger_time alert_name severity mitre_tactic mitre_technique dest src user technique target count

----

| tstats summariesonly=t allow_old_summaries=t count min(_time) as _time
  from datamodel=Endpoint.Image_Loads
  where nodename=Image_Loads
  by Image_Loads.dest Image_Loads.user Image_Loads.process Image_Loads.process_path Image_Loads.parent_process Image_Loads.loaded_module Image_Loads.loaded_module_path Image_Loads.process_signed Image_Loads.module_signed
| rename Image_Loads.* as *
| eval dll_path=loaded_module_path
| eval loaded_dll=loaded_module
| eval signed_status=case(
    module_signed="false" OR module_signed="unsigned", "Unsigned DLL",
    module_signed="true" OR module_signed="signed", "Signed DLL",
    true(), "Unknown"
  )
| eval nonstandard_path=if(
    match(lower(dll_path), "\\\\users\\\\|\\\\programdata\\\\|\\\\temp\\\\|\\\\appdata\\\\|\\\\perflogs\\\\|\\\\public\\\\")
    OR match(lower(dll_path), "^.:\\\\temp\\\\")
    OR match(lower(dll_path), "^.:\\\\windows\\\\temp\\\\"),
    1, 0
  )
| eval legit_parent=if(
    process_signed="true" OR process_signed="signed"
    OR like(lower(process), "%rundll32.exe")
    OR like(lower(process), "%regsvr32.exe")
    OR like(lower(process), "%msiexec.exe")
    OR like(lower(process), "%svchost.exe")
    OR like(lower(process), "%dllhost.exe"),
    1, 0
  )
| eval known_pair=if(
    (like(lower(process), "%rundll32.exe") AND like(lower(dll_path), "%\\appdata\\%"))
    OR (like(lower(process), "%regsvr32.exe") AND like(lower(dll_path), "%\\temp\\%"))
    OR (like(lower(process), "%msiexec.exe") AND like(lower(dll_path), "%\\users\\%")),
    1, 0
  )
| where legit_parent=1 AND (nonstandard_path=1 OR signed_status="Unsigned DLL" OR known_pair=1)
| eval expected_path="System32 or application install directory"
| eval alert_name=case(
    known_pair=1 AND signed_status="Unsigned DLL", "DLL Sideloading/Hijacking - Known Suspicious Pair with Unsigned DLL",
    known_pair=1, "DLL Sideloading/Hijacking - Known Suspicious Pair",
    nonstandard_path=1 AND signed_status="Unsigned DLL", "DLL Sideloading/Hijacking - Unsigned DLL from Non-Standard Path",
    nonstandard_path=1, "DLL Sideloading/Hijacking - DLL Loaded from Non-Standard Path",
    signed_status="Unsigned DLL", "DLL Sideloading/Hijacking - Unsigned DLL Loaded by Signed Process",
    true(), "DLL Sideloading/Hijacking - Suspicious Module Load"
  )
| eval severity=case(
    known_pair=1 AND signed_status="Unsigned DLL", "High",
    nonstandard_path=1 AND signed_status="Unsigned DLL", "High",
    known_pair=1 OR signed_status="Unsigned DLL", "Medium",
    true(), "Low"
  )
| eval mitre_tactic="Privilege Escalation"
| eval mitre_technique="T1574.002 - Hijack Execution Flow: DLL Side-Loading"
| rename _time as trigger_time
| table trigger_time alert_name severity mitre_tactic mitre_technique dest user parent_process process process_path loaded_dll dll_path expected_path signed_status count
