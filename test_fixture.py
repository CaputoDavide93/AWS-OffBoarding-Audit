import json, random
from datetime import datetime, timedelta, timezone
random.seed(11)

ORG = ["111122223333","444455556666","777788889999","222233334444"]
EXT = "908877665544"
accts = [("111122223333","prod-platform"),("444455556666","data-lake"),
         ("777788889999","sandbox-dev"),("222233334444","shared-services")]
regions = ["eu-west-1","eu-west-2","us-east-1"]

routine = ["RunInstances","PutObject","CreateBucket","UpdateFunctionCode","AssumeRole",
           "ConsoleLogin","CreateSecurityGroup","PutRule","ModifyDBInstance","RegisterTaskDefinition",
           "DescribeInstances","ListBuckets","CreateSnapshot"]

# events with realistic request parameters that should trip the content detectors
spicy = [
 ("CreateAccessKey", '{"userName":"svc-deploy-legacy"}'),
 ("UpdateAssumeRolePolicy", '{"roleName":"CrossAdminAccess","policyDocument":"{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":{\\"AWS\\":[\\"arn:aws:iam::'+EXT+':root\\"]},\\"Action\\":\\"sts:AssumeRole\\"}]}"}'),
 ("PutRolePolicy", '{"roleName":"FAKEROLE","policyName":"ROGUE","policyDocument":"{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"NotAction\\":\\"s3:ListBucket\\",\\"NotResource\\":\\"arn:aws:s3:::ct-logs\\"}]}"}'),
 ("ModifySnapshotAttribute", '{"snapshotId":"snap-0a1b","attributeType":"createVolumePermission","createVolumePermission":{"add":[{"userId":"'+EXT+'"}]}}'),
 ("PutBucketLifecycleConfiguration", '{"bucketName":"prod-analytics","LifecycleConfiguration":{"Rule":[{"ID":"cleanup","Status":"Enabled","Expiration":{"Days":1}}]}}'),
 ("AuthorizeSecurityGroupIngress", '{"groupId":"sg-04f2","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}'),
 ("CreateFunctionUrlConfig", '{"FunctionName":"internal-helper","AuthType":"NONE"}'),
 ("UpdateFunctionConfiguration", '{"functionName":"invoice-processor","layers":["arn:aws:lambda:eu-west-1:111122223333:layer:common-deps:7"]}'),
 ("StopLogging", '{"name":"management-events"}'),
 ("DeleteDBInstance", '{"dBInstanceIdentifier":"reporting-db","skipFinalSnapshot":true}'),
 ("PutBucketReplication", '{"bucketName":"customer-data","ReplicationConfiguration":{"Rule":{"Destination":{"Bucket":"arn:aws:s3:::mirror-'+EXT+'"}}}}'),
 ("BatchGetSecretValue", '{"filters":[{"key":"tag-key","values":["prod"]}]}'),
 ("CreateUser", '{"userName":"build-agent-2"}'),
 ("AttachRolePolicy", '{"roleName":"FAKEROLE","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}'),
 ("SendCommand", '{"documentName":"AWS-RunShellScript","instanceIds":["i-0021df"]}'),
 ("ScheduleKeyDeletion", '{"keyId":"1234abcd","pendingWindowInDays":7}'),
 ("PublishLayerVersion", '{"layerName":"common-deps"}'),
 ("DeleteFlowLogs", '{"flowLogIds":["fl-0912"]}'),
]

now = datetime(2026, 8, 20, 17, 0, tzinfo=timezone.utc)
rows = []
for i in range(260):
    late = i > 215
    use_spicy = (late and random.random() < 0.5) or random.random() < 0.13
    if use_spicy:
        name, params = random.choice(spicy)
    else:
        name, params = random.choice(routine), '{"instanceType":"t3.medium"}'
    off = timedelta(days=random.uniform(0, 4) if late else random.uniform(0, 30))
    ts = now - off
    if late and random.random() < 0.5:
        ts = ts.replace(hour=random.choice([2, 23, 5]))
    a = random.choice(accts)
    rows.append({
        "time_utc": ts.isoformat(), "account_id": a[0], "account_name": a[1],
        "region": random.choice(regions), "event_source": "ec2.amazonaws.com",
        "event_name": name, "matched_on": "leaver@example.com",
        "principal_arn": f"arn:aws:sts::{a[0]}:assumed-role/AWSReservedSSO_Admin_x/leaver@example.com",
        "source_ip": random.choice(["82.14.9.201","82.14.9.201","82.14.9.201","185.62.44.7"]),
        "user_agent": "aws-cli/2.15.0",
        "error_code": random.choice(["","","","","AccessDenied"]) if late else "",
        "resources": random.choice(["vol-0a1b2c3d","snap-9f8e7d6c","prod-analytics",""]),
        "request_params": params,
    })
json.dump(rows, open("sample.json","w"), indent=1)
manifest = {
    "schema_version": 2,
    "run_id": "aws-offboarding-fixture",
    "input_hash": "fixture",
    "created_at": now.isoformat(),
    "status": "complete",
    "subject": "leaver@example.com",
    "window": {
        "start": min(row["time_utc"] for row in rows),
        "end": max(row["time_utc"] for row in rows),
    },
    "source": "synthetic_fixture",
    "event_scope": "management",
    "include_reads": True,
    "request_params_truncated": 0,
    "accounts_discovered": len(accts),
    "accounts_selected": len(accts),
    "requested_units": len(accts) * len(regions),
    "successful_units": len(accts) * len(regions),
    "failed_units": 0,
    "events_matched": len(rows),
    "limitations": [
        "Synthetic fixture data; no AWS account was queried.",
        "CloudTrail Event History covers management events only.",
    ],
}
json.dump(manifest, open("sample.manifest.json", "w"), indent=1)
state = {
    "schema_version": 1,
    "checked_at": now.isoformat(),
    "source": "synthetic_fixture",
    "targets": {
        "user:svc-deploy-legacy": {"status": "active", "detail": "Synthetic active key."},
        "role:crossadminaccess": {"status": "active", "detail": "Synthetic role exists."},
        "snapshot:snap-0a1b": {"status": "removed", "detail": "Synthetic share removed."},
        "bucket:prod-analytics": {"status": "removed", "detail": "Synthetic rule removed."},
        "function:internal-helper": {"status": "active", "detail": "Synthetic URL exists."},
        "database:reporting-db": {"status": "removed", "detail": "Synthetic database absent."},
    },
}
json.dump(state, open("sample.state.json", "w"), indent=1)
baseline = {
    "schema_version": 1,
    "label": "Synthetic platform peers",
    "sample_size": 12,
    "events": {
        "CreateAccessKey": {"mean": 0.2, "stddev": 0.4},
        "UpdateAssumeRolePolicy": {"mean": 0.4, "stddev": 0.5},
        "StopLogging": {"mean": 0, "stddev": 0},
        "DeleteFlowLogs": {"mean": 0, "stddev": 0},
        "RunInstances": {"mean": 18, "stddev": 6},
    },
}
json.dump(baseline, open("sample.baseline.json", "w"), indent=1)
print(len(rows), "sample events")
