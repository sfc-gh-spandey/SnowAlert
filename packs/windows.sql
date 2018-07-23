/*
SnowAlert Analytics Pack: Windows
 */


/*
Unapproved Process
 */
query_spec windows_unapproved_process {
  AffectedEnv = ["Prod"]
  AffectedObject = ["{} on {}", 4.0, 1.0]
  AffectedObjectType = ["Windows Server"]
  AlertType = ["Unapproved Windows Process Started"]
  EventTime = ["{}", 0.0]
  Description = ["Unapproved process {} ran on {} by user {}", 4.0, 1.0, 3.0 ]
  Detector = ["SnowAlert"]
  EventData = ["{}", 5.0]
  Query = <<QUERY
select to_timestamp_ntz(substr(get(xmlget(jsontext, 'System'):"$",7), 26, 30)) as eventtime,
xmlget(xmlget(jsontext, 'System'),'Computer'):"$"::string as computer,
xmlget(jsontext, 'EventData'):"$"[2]:"$"::string as domain_name,
xmlget(jsontext, 'EventData'):"$"[1]:"$"::string as user_name,
process_name::string as process_name, jsontext from
(select jsontext, xmlget(jsontext, 'EventData'):"$"[5]:"$" as process_name,
xmlget(xmlget($1, 'System'),'EventID'):"$" as event_id from windows_events.public.windows_logs
where event_id = '4688') left join windows_events.public.approved_processes on process_name = windows_events.public.approved_processes.path
where windows_events.public.approved_processes.path is null
and eventtime > dateadd(hour, -1, current_timestamp());
  QUERY
  Severity = ["2"]
}


/*
Anomalous USB Usage
 */
query_spec windows_anomalous_usb_usage {
  AffectedEnv = ["Dev"]
  AffectedObject = ["{} on {}", 4.0, 1.0]
  AffectedObjectType = ["Windows Server"]
  AlertType = ["Anomalous USB Usage"]
  EventTime = ["{}", 0.0]
  Description = ["Anomalous USB Usage on {} by user {}", 1.0, 3.0 ]
  Detector = ["SnowAlert"]
  EventData = ["{}", 5.0]
  Query = <<QUERY
select to_timestamp_ntz(substr(get(xmlget(jsontext, 'System'):"$",7), 26, 30)) as eventtime,
xmlget(xmlget(jsontext, 'System'),'Computer'):"$"::string as computer,
xmlget(jsontext, 'EventData'):"$"[2]:"$"::string as domain_name,
xmlget(jsontext, 'EventData'):"$"[1]:"$"::string as user_name,
process_name::string as process_name, jsontext from
(select jsontext,
xmlget(xmlget($1, 'System'),'EventID'):"$" as event_id from windows_events.public.windows_logs
where event_id = '20001')
and eventtime > dateadd(hour, -1, current_timestamp());
  QUERY
  Severity = ["3"]
}


/*
Long Command Line

Reference: https://www.sans.org/summit-archives/file/summit-archive-1511980157.pdf
 */
query_spec windows_long_command_line {
  AffectedEnv = ["Dev"]
  AffectedObject = ["{} on {}", 4.0, 1.0]
  AffectedObjectType = ["Windows Server"]
  AlertType = ["Windows Long Command Line"]
  EventTime = ["{}", 0.0]
  Description = ["Command line with suspicious length executed on {} by user {}", 1.0, 3.0 ]
  Detector = ["SnowAlert"]
  EventData = ["{}", 5.0]
  Query = <<QUERY
select to_timestamp_ntz(substr(get(xmlget(jsontext, 'System'):"$",7), 26, 30)) as eventtime,
xmlget(xmlget(jsontext, 'System'),'Computer'):"$"::string as computer,
xmlget(jsontext, 'EventData'):"$"[2]:"$"::string as domain_name,
xmlget(jsontext, 'EventData'):"$"[1]:"$"::string as user_name,
process_name::string as process_name, jsontext from
(select jsontext,
command,
xmlget(xmlget($1, 'System'),'EventID'):"$" as event_id from windows_events.public.windows_logs
where event_id in ('4688')
and length(command) > 500
and eventtime > dateadd(hour, -1, current_timestamp());
  QUERY
  Severity = ["3"]
}


/*
Suspicious CMD.EXE Activity
 */
query_spec windows_suspicious_cmd_activity {
  AffectedEnv = ["Dev"]
  AffectedObject = ["{} on {}", 4.0, 1.0]
  AffectedObjectType = ["Windows Server"]
  AlertType = ["Suspicious CMD.EXE Activity"]
  EventTime = ["{}", 0.0]
  Description = ["An unusual parent process ran CMD.EXE on {} by user {}", 1.0, 3.0 ]
  Detector = ["SnowAlert"]
  EventData = ["{}", 5.0]
  Query = <<QUERY
select to_timestamp_ntz(substr(get(xmlget(jsontext, 'System'):"$",7), 26, 30)) as eventtime,
xmlget(xmlget(jsontext, 'System'),'Computer'):"$"::string as computer,
xmlget(jsontext, 'EventData'):"$"[2]:"$"::string as domain_name,
xmlget(jsontext, 'EventData'):"$"[1]:"$"::string as user_name,
process_name::string as process_name, jsontext from
(select jsontext,
parent_process,
process_name,
xmlget(xmlget($1, 'System'),'EventID'):"$" as event_id from windows_events.public.windows_logs
where event_id in ('4688')
and process_name = 'cmd.exe'
and parent_process not in ('explorer.exe', 'cmd.exe')
and eventtime > dateadd(hour, -1, current_timestamp());
  QUERY
  Severity = ["3"]
}


/*
Suspicious REGEDIT.EXE Activity
 */
query_spec windows_suspicious_cmd_activity {
  AffectedEnv = ["Dev"]
  AffectedObject = ["{} on {}", 4.0, 1.0]
  AffectedObjectType = ["Windows Server"]
  AlertType = ["Suspicious REGEDIT.EXE Activity"]
  EventTime = ["{}", 0.0]
  Description = ["An unusual parent process ran REGEDIT.EXE on {} by user {}", 1.0, 3.0 ]
  Detector = ["SnowAlert"]
  EventData = ["{}", 5.0]
  Query = <<QUERY
select to_timestamp_ntz(substr(get(xmlget(jsontext, 'System'):"$",7), 26, 30)) as eventtime,
xmlget(xmlget(jsontext, 'System'),'Computer'):"$"::string as computer,
xmlget(jsontext, 'EventData'):"$"[2]:"$"::string as domain_name,
xmlget(jsontext, 'EventData'):"$"[1]:"$"::string as user_name,
process_name::string as process_name, jsontext from
(select jsontext,
parent_process,
process_name,
xmlget(xmlget($1, 'System'),'EventID'):"$" as event_id from windows_events.public.windows_logs
where event_id in ('4688')
and process_name = 'regedit.exe'
and parent_process not in ('explorer.exe', 'cmd.exe')
and eventtime > dateadd(hour, -1, current_timestamp());
  QUERY
  Severity = ["3"]
}


/*
Suspicious POWERSHELL.EXE Activity
 */
query_spec windows_suspicious_cmd_activity {
  AffectedEnv = ["Dev"]
  AffectedObject = ["{} on {}", 4.0, 1.0]
  AffectedObjectType = ["Windows Server"]
  AlertType = ["Suspicious POWERSHELL.EXE Activity"]
  EventTime = ["{}", 0.0]
  Description = ["An unusual parent process ran POWERSHELL.EXE on {} by user {}", 1.0, 3.0 ]
  Detector = ["SnowAlert"]
  EventData = ["{}", 5.0]
  Query = <<QUERY
select to_timestamp_ntz(substr(get(xmlget(jsontext, 'System'):"$",7), 26, 30)) as eventtime,
xmlget(xmlget(jsontext, 'System'),'Computer'):"$"::string as computer,
xmlget(jsontext, 'EventData'):"$"[2]:"$"::string as domain_name,
xmlget(jsontext, 'EventData'):"$"[1]:"$"::string as user_name,
process_name::string as process_name, jsontext from
(select jsontext,
parent_process,
process_name,
xmlget(xmlget($1, 'System'),'EventID'):"$" as event_id from windows_events.public.windows_logs
where event_id in ('4688')
and process_name = 'powershell.exe'
and parent_process not in ('explorer.exe', 'cmd.exe')
and eventtime > dateadd(hour, -1, current_timestamp());
  QUERY
  Severity = ["3"]
