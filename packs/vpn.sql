/*
SnowAlert Analytics Pack: VPN
 */


/*
Geographically Distant Logins for User
 */
CREATE OR REPLACE VIEW vpn_distant_logins_v AS
SELECT concat('Office VPN - ', office) AS affected_environment,
       username AS affected_object,
       'User' AS affectedobjecttype,
       'VPN Distant Logins' AS alerttype,
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