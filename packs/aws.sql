/*
SnowAlert Analytics Pack: AWS
*/


/*
Access Denied
 */
CREATE OR REPLACE VIEW aws_access_denied_v AS
SELECT ('AWS Account: ' || cloudtrail.RECIPIENT_ACCOUNT_ID || cloudtrail.DEPLOYMENT) as affectedenv,
       cloudtrail.EVENT_NAME AS affectedobject,
       'AWS API Action' AS affectedobjecttype,
       'AWS Access Denied' AS alerttype,
       cloudtrail.EVENT_TIME AS eventtime,
       ('Access Denied for user ' ||
        case
          when cloudtrail.USER_IDENTITY_TYPE = 'IAMUser' then cloudtrail.USER_IDENTITY_USERNAME
          when cloudtrail.USER_IDENTITY_TYPE = 'Root' then 'Root'
          when cloudtrail.USER_IDENTITY_TYPE = 'AssumedRole' then cloudtrail.USER_IDENTITY_SESSION_CONTEXT_SESSION_ISSUER_USER_NAME
          when cloudtrail.USER_IDENTITY_TYPE = 'AWSAccount' then cloudtrail.USER_IDENTITY_ACCOUNTID
          when cloudtrail.USER_IDENTITY_TYPE = 'AWSService' then cloudtrail.USER_IDENTITY_INVOKEDBY
        end ||
        ' trying to ' ||
        cloudtrail.EVENT_NAME || ' from ' ||
        case
          when cloudtrail.SOURCE_IP_ADDRESS = '4.3.2.1' then 'Your Network Name'
          when ip_sources.ip_source is not null then ip_sources.ip_source
          else cloudtrail.SOURCE_IP_ADDRESS
       end) AS description,
       'SnowAlert' AS detector,
       cloudtrail.RAW as eventdata,
       '3' AS severity,
       '9f5b849317e941a5ab9d380da31e6906' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'cloudtrail_aws_access_denied_v' AS event_def,
       1 AS version
  FROM prod.prod.cloudtrail_v AS cloudtrail
  LEFT JOIN prod.prod.ip_sources  AS ip_sources
    ON prod.prod.IS_IN_CIDR(cloudtrail.SOURCE_IP_ADDRESS, ip_sources.cidr)
 WHERE 1=1
   AND cloudtrail.ERROR_CODE = 'AccessDenied';


/*
Wide Open Security Group
*/
CREATE OR REPLACE VIEW aws_wide_open_security_group_v AS
SELECT ('AWS Account: '|| cloudtrail.DEPLOYMENT ||' ('|| cloudtrail.RECIPIENT_ACCOUNT_ID ||')') as affectedenv,
       cloudtrail.REQUEST_PARAMETERS:groupId as affectedobject,
       'Security Group' as affected_object_type,
       'Wide Open Security Group' as alert_type,
       cloudtrail.EVENT_TIME as event_time,
       ('User '||
       case
         when cloudtrail.USER_IDENTITY_TYPE = 'IAMUser' then cloudtrail.USER_IDENTITY_USERNAME
         when cloudtrail.USER_IDENTITY_TYPE = 'Root' then 'Root'
         when cloudtrail.USER_IDENTITY_TYPE = 'AssumedRole' then cloudtrail.USER_IDENTITY_SESSION_CONTEXT_SESSION_ISSUER_USER_NAME
         when cloudtrail.USER_IDENTITY_TYPE = 'AWSAccount' then cloudtrail.USER_IDENTITY_ACCOUNTID
         when cloudtrail.USER_IDENTITY_TYPE = 'AWSService' then cloudtrail.USER_IDENTITY_INVOKEDBY
       end ||' performed '||
       cloudtrail.EVENT_NAME || ' on ' ||
       cloudtrail.REQUEST_PARAMETERS:groupId ||
       ', working from ' ||
       case
         when cloudtrail.SOURCE_IP_ADDRESS = '4.3.2.1' then 'Your Network Name'
         when ip_sources.ip_source is not null then ip_sources.ip_source
         else cloudtrail.SOURCE_IP_ADDRESS
       end) AS description,
       'SnowAlert' as detector,
       cloudtrail.RAW as event_data,
       '2' as severity,
       hash(raw) as event_hash,
       current_database() as database,
       current_schema() as schema,
       'wide_open_security_group_v' as event_def,
       1 as version
  FROM prod.prod.cloudtrail_v  AS cloudtrail
  LEFT JOIN prod.prod.ip_sources AS ip_sources
    ON prod.prod.IS_IN_CIDR(cloudtrail.SOURCE_IP_ADDRESS, ip_sources.cidr)
 WHERE 1=1
   AND cloudtrail.REQUEST_PARAMETERS LIKE '%"0.0.0.0/0%'
   AND cloudtrail.EVENT_NAME = 'AuthorizeSecurityGroupIngress';


/*
Security Group Changes
 */
create or replace view cloudtrail_security_group_changes_v as
  select ('AWS Account: '|| cloudtrail.DEPLOYMENT ||' ('|| cloudtrail.RECIPIENT_ACCOUNT_ID ||')') as affectedenv,
  cloudtrail.REQUEST_PARAMETERS:groupId as affectedobject,
  'Security Group' as affectedobjecttype,
  'Security Group Ingress/Egress Change' as alerttype,
  cloudtrail.EVENT_TIME as eventtime,
  ('User '|| case
    when cloudtrail.USER_IDENTITY_TYPE = 'IAMUser' then cloudtrail.USER_IDENTITY_USERNAME
    when cloudtrail.USER_IDENTITY_TYPE = 'Root' then 'Root'
    when cloudtrail.USER_IDENTITY_TYPE = 'AssumedRole' then cloudtrail.USER_IDENTITY_SESSION_CONTEXT_SESSION_ISSUER_USER_NAME
    when cloudtrail.USER_IDENTITY_TYPE = 'AWSAccount' then cloudtrail.USER_IDENTITY_ACCOUNTID
    when cloudtrail.USER_IDENTITY_TYPE = 'AWSService' then cloudtrail.USER_IDENTITY_INVOKEDBY
end ||' performed '|| cloudtrail.EVENT_NAME ||' on '|| cloudtrail.REQUEST_PARAMETERS:groupId ||', working from '|| case
    when cloudtrail.SOURCE_IP_ADDRESS = '4.3.2.1' then 'Your Network Name'
    when ip_sources.ip_source is not null then ip_sources.ip_source
    else cloudtrail.SOURCE_IP_ADDRESS
end ||'.') as description,
  'SnowAlert' as detector,
  cloudtrail.RAW as eventdata,
  '849dcb69002840788580ca1c470404df' as guid,
  hash(raw) as event_hash,
  current_database() as database,
  current_schema() as schema,
  'cloudtrail_security_group_changes_v' as event_def,
  1 as version

  FROM prod.prod.cloudtrail_v  AS cloudtrail
  LEFT JOIN prod.prod.ip_sources AS ip_sources
    ON prod.prod.IS_IN_CIDR(cloudtrail.SOURCE_IP_ADDRESS, ip_sources.cidr)
  WHERE 1=1
   AND (cloudtrail.EVENT_SOURCE = 'ec2.amazonaws.com')
   AND (cloudtrail.EVENT_NAME  = 'AuthorizeSecurityGroupIngress'
    OR cloudtrail.EVENT_NAME  = 'AuthorizeSecurityGroupEgress');


/*
Root Account Activity
 */
CREATE OR REPLACE VIEW aws_root_activity_v AS
SELECT ('AWS Account: ' || cloudtrail.RECIPIENT_ACCOUNT_ID || cloudtrail.DEPLOYMENT) as affectedenv,
       'AWS Root Account' AS affectedobject,
       'AWS Root Account' AS affectedobjecttype,
       'Activity by Root' AS alerttype,
       cloudtrail.EVENT_TIME AS eventtime,
       ('User root performed ' ||
        cloudtrail.EVENT_NAME ||
       ', working from ' ||
       case
         when cloudtrail.SOURCE_IP_ADDRESS = '4.3.2.1' then 'Your Network Name'
         when ip_sources.ip_source is not null then ip_sources.ip_source
         else cloudtrail.SOURCE_IP_ADDRESS
       end) AS description,
       'SnowAlert' AS detector,
       cloudtrail.RAW as eventdata,
       '2' AS severity,
       '431da83118d54a6e9eab79d8bbb29eb4' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'cloudtrail_root_activity_v' AS event_def,
       1 AS version
 FROM prod.prod.cloudtrail_v AS cloudtrail
   LEFT JOIN prod.prod.ip_sources AS ip_sources
    ON prod.prod.IS_IN_CIDR(cloudtrail.SOURCE_IP_ADDRESS, ip_sources.cidr)
  WHERE 1=1
    AND cloudtrail.USER_IDENTITY_TYPE = 'Root'
    AND cloudtrail.SOURCE_IP_ADDRESS <> 'support.amazonaws.com';


/*
S3 Security Activity
 */
CREATE OR REPLACE VIEW aws_s3_security_activity_v AS
SELECT ('AWS Account: ' || cloudtrail.RECIPIENT_ACCOUNT_ID || cloudtrail.DEPLOYMENT) as affectedenv,
       cloudtrail.REQUEST_PARAMETERS:bucketName AS affectedobject,
       'S3 Bucket' AS affectedobjecttype,
       'S3 Security Activity' AS alerttype,
       cloudtrail.EVENT_TIME AS eventtime,
       ('User ' ||
        case
          when cloudtrail.USER_IDENTITY_TYPE = 'IAMUser' then cloudtrail.USER_IDENTITY_USERNAME
          when cloudtrail.USER_IDENTITY_TYPE = 'Root' then 'Root'
          when cloudtrail.USER_IDENTITY_TYPE = 'AssumedRole' then cloudtrail.USER_IDENTITY_SESSION_CONTEXT_SESSION_ISSUER_USER_NAME
          when cloudtrail.USER_IDENTITY_TYPE = 'AWSAccount' then cloudtrail.USER_IDENTITY_ACCOUNTID
          when cloudtrail.USER_IDENTITY_TYPE = 'AWSService' then cloudtrail.USER_IDENTITY_INVOKEDBY
        end ||
        ' performed ' ||
        cloudtrail.EVENT_NAME ||
       ' on '  || cloudtrail.REQUEST_PARAMETERS:bucketName ||
       ', working from ' ||
       case
         when cloudtrail.SOURCE_IP_ADDRESS = '4.3.2.1' then 'Your Network Name'
         when ip_sources.ip_source is not null then ip_sources.ip_source
         else cloudtrail.SOURCE_IP_ADDRESS
       end) AS description,
       'SnowAlert' AS detector,
       cloudtrail.RAW as eventdata,
       '2' AS severity,
       '7e608a30799049cf8b2be5a5ed0209cc' AS guid,
       hash(raw) AS event_hash,
       current_database() AS database,
       current_schema() AS schema,
       'cloudtrail_s3_security_activity_v' AS event_def,
       1 AS version
  FROM prod.prod.cloudtrail_v AS cloudtrail
  LEFT JOIN prod.prod.ip_sources AS ip_sources
    ON prod.prod.IS_IN_CIDR(cloudtrail.SOURCE_IP_ADDRESS, ip_sources.cidr)
 WHERE 1=1
   AND cloudtrail.EVENT_SOURCE = 's3.amazonaws.com'
   AND (cloudtrail.EVENT_NAME  = 'DeleteBucket'
    OR cloudtrail.EVENT_NAME  = 'DeleteBucketLifeCycle'
    OR cloudtrail.EVENT_NAME  = 'DeleteBucketTagging'
    OR cloudtrail.EVENT_NAME  = 'PutBucketAcl'
    OR cloudtrail.EVENT_NAME  = 'PutBucketLifecycle'
    OR cloudtrail.EVENT_NAME  = 'PutBucketPolicy'
    OR cloudtrail.EVENT_NAME  = 'PutBucketReplication'
    OR cloudtrail.EVENT_NAME  = 'PutBucketLogging');
