"""Recorded AWS CloudTrail / GuardDuty fixtures for mock-mode responses (#100).

Shapes mirror the provider surfaces the live connector will call:

- ``CLOUDTRAIL_FIXTURE_EVENTS`` — CloudTrail record objects (``eventTime`` /
  ``eventName`` / ``eventSource`` / ``userIdentity`` / ``sourceIPAddress`` /
  ``awsRegion`` / ``errorCode``), the LookupEvents mock's data source.
- ``GUARDDUTY_FIXTURE_FINDINGS`` — GuardDuty finding objects (``type`` /
  ``severity`` / ``resource`` / ``service``).

The fixtures tell one coherent compromised-access-key story for the IAM
user ``ci-deploy``:

* Legitimate baseline: ``ci-deploy`` pushes deploy artifacts to S3 from the
  build subnet (10.0.9.5, us-east-1), and ``ops-admin`` does routine EC2
  describes.
* The stolen key surfaces from 198.51.100.200 (eu-west-3 — a region the org
  never uses): ``GetCallerIdentity`` recon, ``ListBuckets``, an initially
  **denied** ``CreateAccessKey``, then persistence — ``CreateUser``
  (``svc-maint``) + ``AttachUserPolicy`` (AdministratorAccess) — and a
  denied ``RunInstances`` (cryptomining attempt).
* GuardDuty corroborates: credential-exfiltration (severity 8.2) and
  malicious-IP-caller recon (5.1) findings on the same access key /
  principal, plus an unrelated low-severity S3 public-access finding on
  another resource (the noise floor).

Join keys: ``userIdentity.userName`` / ``resource.accessKeyDetails.userName``
carries the principal across CloudTrail ↔ GuardDuty;
``userIdentity.accessKeyId`` / ``accessKeyDetails.accessKeyId`` ties the
stolen key; ``sourceIPAddress`` / ``remoteIpDetails.ipAddressV4`` ties the
attacker infrastructure.
"""

from __future__ import annotations

from typing import Any

# The stolen key and the attacker's origin, shared across both surfaces.
STOLEN_ACCESS_KEY_ID = "AKIAEXAMPLE00STOLEN0"
ATTACKER_IP = "198.51.100.200"

CLOUDTRAIL_FIXTURE_EVENTS: list[dict[str, Any]] = [
    # --- legitimate baseline ---
    {
        "eventTime": "2026-06-25T08:10:00Z",
        "eventName": "PutObject",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.9.5",
        "userAgent": "aws-cli/2.17.0",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {"bucketName": "acme-deploy-artifacts", "key": "app-v341.tar.gz"},
        "errorCode": None,
    },
    {
        "eventTime": "2026-06-25T09:00:00Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.2.14",
        "userAgent": "console.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ops-admin",
            "arn": "arn:aws:iam::123456789012:user/ops-admin",
            "accessKeyId": "ASIAEXAMPLE00OPSADM0",
        },
        "requestParameters": {},
        "errorCode": None,
    },
    # --- the stolen key surfaces from attacker infrastructure ---
    {
        "eventTime": "2026-06-25T11:02:11Z",
        "eventName": "GetCallerIdentity",
        "eventSource": "sts.amazonaws.com",
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "Boto3/1.34.100",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {},
        "errorCode": None,
    },
    {
        "eventTime": "2026-06-25T11:03:40Z",
        "eventName": "ListBuckets",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "Boto3/1.34.100",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {},
        "errorCode": None,
    },
    {
        "eventTime": "2026-06-25T11:05:02Z",
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "Boto3/1.34.100",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {"userName": "ci-deploy"},
        "errorCode": "AccessDenied",
    },
    {
        "eventTime": "2026-06-25T11:07:19Z",
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "Boto3/1.34.100",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {"userName": "svc-maint"},
        "errorCode": None,
    },
    {
        "eventTime": "2026-06-25T11:08:03Z",
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "Boto3/1.34.100",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {
            "userName": "svc-maint",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "errorCode": None,
    },
    {
        "eventTime": "2026-06-25T11:12:44Z",
        "eventName": "RunInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "eu-west-3",
        "sourceIPAddress": ATTACKER_IP,
        "userAgent": "Boto3/1.34.100",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "ci-deploy",
            "arn": "arn:aws:iam::123456789012:user/ci-deploy",
            "accessKeyId": STOLEN_ACCESS_KEY_ID,
        },
        "requestParameters": {"instanceType": "p4d.24xlarge", "maxCount": 8},
        "errorCode": "AccessDenied",
    },
]


GUARDDUTY_FIXTURE_FINDINGS: list[dict[str, Any]] = [
    {
        "id": "gd-finding-0000000000000001",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.2,
        "region": "eu-west-3",
        "createdAt": "2026-06-25T11:06:00Z",
        "updatedAt": "2026-06-25T11:15:00Z",
        "title": "Credentials for IAM user ci-deploy used from an external IP address",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": STOLEN_ACCESS_KEY_ID,
                "userName": "ci-deploy",
                "userType": "IAMUser",
            },
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "CreateUser",
                    "serviceName": "iam.amazonaws.com",
                    "remoteIpDetails": {"ipAddressV4": ATTACKER_IP},
                },
            },
        },
    },
    {
        "id": "gd-finding-0000000000000002",
        "type": "Recon:IAMUser/MaliciousIPCaller.Custom",
        "severity": 5.1,
        "region": "eu-west-3",
        "createdAt": "2026-06-25T11:04:00Z",
        "updatedAt": "2026-06-25T11:04:00Z",
        "title": "API GetCallerIdentity invoked from a known malicious IP",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": STOLEN_ACCESS_KEY_ID,
                "userName": "ci-deploy",
                "userType": "IAMUser",
            },
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "GetCallerIdentity",
                    "serviceName": "sts.amazonaws.com",
                    "remoteIpDetails": {"ipAddressV4": ATTACKER_IP},
                },
            },
        },
    },
    # Unrelated low-severity hygiene finding — the noise floor.
    {
        "id": "gd-finding-0000000000000003",
        "type": "Policy:S3/BucketPublicAccessGranted",
        "severity": 2.0,
        "region": "us-east-1",
        "createdAt": "2026-06-24T16:00:00Z",
        "updatedAt": "2026-06-24T16:00:00Z",
        "title": "S3 bucket acme-marketing-assets was made publicly accessible",
        "resource": {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{"name": "acme-marketing-assets"}],
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "PutBucketPolicy",
                    "serviceName": "s3.amazonaws.com",
                    "remoteIpDetails": {"ipAddressV4": "10.0.2.14"},
                },
            },
        },
    },
]
