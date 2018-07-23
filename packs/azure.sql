/*
SnowAlert Analytics Pack: Azure
 */


/*
Login Failure
 */
query_spec azure_login_failure {
  AffectedEnv = ["Azure - {}", 1.0]
  AffectedObject = ["{}", 2.0]
  AffectedObjectType = ["Azure Login"]
  AlertType = ["Azure Failed Login"]
  EventTime = ["{}", 0.0]
  Description = ["{} Login Failure Detected For User {} From {} Reason {}", 1.0, 2.0, 3.0, 4.0 ]
  Detector = ["Azure"]
  EventData = ["{}", 5.0]
  GUID = "24095937f5d6400c9cf76b407a6c65f2"
  Query = <<QUERY
SELECT eventtime,
       app_name,
       user_email,
       ip_address,
       fail_reason,
       raw AS event
  FROM prod.prod.azure_aad_signin_v
 WHERE eventtime > dateadd(hour, -1, current_timestamp())
   AND upper(login_status) = 'FAILURE';
QUERY
  Severity = ["5"]
}


/*
Login Without MFA
 */
query_spec azure_login_without_mfa {
  AffectedEnv = ["Azure - {}", 1.0]
  AffectedObject = ["{}", 2.0]
  AffectedObjectType = ["Azure Login"]
  AlertType = ["Azure Login Without MFA"]
  EventTime = ["{}", 0.0]
  Description = ["{} Login Without MFA Detected For User {} From {}", 1.0, 2.0, 3.0 ]
  Detector = ["Azure"]
  EventData = ["{}", 4.0]
  GUID = "e2ff839cf6174770b89dbc640bab9f1e"
  Query = <<QUERY
SELECT eventtime,
       app_name,
       user_email,
       ip_address,
       raw AS event
  FROM prod.prod.azure_aad_signin_v
 WHERE eventtime > dateadd(hour, -1, current_timestamp())
   AND upper(login_status) = 'SUCCESS'
   AND mfa_required = FALSE;
QUERY
  Severity = ["5"]
}


/*
Security Group Change
 */
query_spec azure_security_group_change {
  AffectedEnv = ["Azure - {}", 1.0]
  AffectedObject = ["{}", 2.0]
  AffectedObjectType = ["Azure Networking"]
  AlertType = ["Azure Security Group Change Detected"]
  EventTime = ["{}", 0.0]
  Description = ["Azure {} Change Detected Result {} Resource {}", 2.0, 3.0, 4.0 ]
  Detector = ["Azure"]
  EventData = ["{}", 5.0]
  GUID = "34a308f8084d4f89bfa885ca9a14357c"
  Query = <<QUERY
SELECT eventtime,
       deployment,
       operation_type,
       result_signature,
       resource_id,
       raw AS event
  FROM prod.prod.azure_network_activity_v
 WHERE eventtime > dateadd(hour, -1, current_timestamp())
   AND operation_type = 'NETWORKSECURITYGROUPS';
QUERY
  Severity = ["5"]
}


/*
Wide Open Security Group
 */
query_spec azure_wide_open_security_group {
  AffectedEnv = ["Azure - {}", 1.0]
  AffectedObject = ["{}", 2.0]
  AffectedObjectType = ["Azure Networking"]
  AlertType = ["Azure Open Security Group Rule Detected"]
  EventTime = ["{}", 0.0]
  Description = ["Azure {} Open Security Group Rule Detected Result {} Resource {}", 2.0, 3.0, 4.0 ]
  Detector = ["Azure"]
  EventData = ["{}", 5.0]
  GUID = "7195f5e303a84fe784dd989bef445f53"
  Query = <<QUERY
SELECT eventtime,
       deployment,
       operation_type,
       result_signature,
       resource_id,
       raw AS event
  FROM prod.prod.azure_network_activity_v
 WHERE eventtime > dateadd(hour, -1, current_timestamp())
   AND operation_type = 'NETWORKSECURITYGROUPS'
   AND properties LIKE '%"0.0.0.0/0%';
QUERY
  Severity = ["5"]
}