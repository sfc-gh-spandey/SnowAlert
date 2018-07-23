/*
SnowAlert Analytics Pack: Linux
 */


/*
Kernel Module Changes
 */
CREATE OR REPLACE VIEW linux_kernel_module_changes_v AS
SELECT concat('Servers - ', deployment) AS affectedenv,
       instance_id AS affectedobject,
       'Server' AS affectedobjecttype,
       'Kernel Module Modifications' AS alerttype,
       eventtime,
       ('Command ' || columns:cmdline::string || ' ran on ' || instance_id) AS description,
       name::string as name,
       raw AS eventdata,
       '4' AS severity,
       '9927c56f68a54c488934b004c0c0387e' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'osquery_kernel_module_changes_v' AS event_def,
       deployment,
       1 AS version
  FROM prod.prod.osquery_v
 WHERE 1=1
   AND name = 'process_events'
   AND (columns:cmdline::string like '%insmod%'
        OR columns:cmdline::string like '%rmmod%');


/*
Root Login
 */
CREATE OR REPLACE VIEW linux_root_login_v AS
SELECT concat('Servers - ', deployment) AS affectedenv,
       instance_id AS affectedobject,
       'Server' AS affectedobjecttype,
       'Root Login On Server' AS alerttype,
       eventtime AS eventtime,
       (c_username || ' logged into ' ||
       deployment || ' host ' || c_host || ' ' ||
       instance_id ||
       ' at ' || c_time) AS description,
       'Osquery' AS detector,
       raw AS eventdata,
       '5' AS severity,
       'a04ffb6ea70845049496f91f739776d4' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'osquery_root_login_server_v' AS event_def,
       c_username,
       c_host,
       instance_id,
       c_time
  FROM prod.prod.osquery_last_v
 WHERE 1=1
   AND c_time > dateadd(hour, -1, eventtime)
   AND c_username = 'root';


/*
File Transfers
 */
CREATE OR REPLACE VIEW linux_file_transfers_v AS
SELECT concat('Servers - ', deployment) AS affectedenv,
       instance_id AS affectedobject,
       'Server' AS affectedobjecttype,
       'File Transfers' AS alerttype,
       eventtime,
       ('Command ' || columns:cmdline::string || ' ran on ' || instance_id) AS description,
       name::string as name,
       raw AS eventdata,
       '2' AS severity,
       'e565874872c74f5fa583e10a9632909f' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'osquery_file_transfers_v' AS event_def,
       deployment,
       1 AS version
  FROM prod.prod.osquery_v
 WHERE 1=1
   AND name = 'process_events'
   AND (columns:path::string like '%scp%'
        OR columns:path::string like '%wget%'
        OR columns:path::string like '%curl%');


/*
Privilege Escalation
 */
CREATE OR REPLACE VIEW osquery_host_privilege_escalation_v AS
SELECT concat('Servers - ', deployment) AS affectedenv,
       instance_id AS affectedobject,
       'Server' AS affectedobjecttype,
       'Privilege Escalation on Host' AS alerttype,
       eventtime,
       ('Command ' || columns:cmdline::string || ' ran on ' || instance_id) AS description,
       name::string as name,
       raw AS eventdata,
       '2' AS severity,
       '7a2a0bfefa674b4090328c0bae27edbe' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'osquery_host_privilege_escalation_v' AS event_def,
       deployment,
       1 AS version
  FROM prod.prod.osquery_v
 WHERE 1=1
   AND name = 'process_events'
   AND columns:path::string = '/usr/bin/sudo';