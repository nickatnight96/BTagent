"""``bt init-storage`` — idempotently create the evidence bucket.

Nothing in the product ever called ``create_bucket``, so ``GET /health/ready``
head_bucket'd a bucket that had never been made and a fresh MinIO reported
``s3: down`` until an operator created it by hand through the console.

To be accurate about what the bucket is *for*: nothing writes to it yet.
There is no ``put_object``/``upload_fileobj`` anywhere in the product,
``EvidenceRow`` is declared but never inserted, and no route serves evidence.
The bucket is provisioned ahead of evidence storage, and the readiness check
reports it without gating on it (see ``api/v1/health.py``
``S3_GATES_READINESS``). Creating it up front is still worth doing — it makes
the dependency real and checkable before the first upload, rather than on the
day it lands.

This command closes that gap from *inside* the backend image, reading the same
:class:`~btagent_backend.config.Settings` fields the readiness probe reads, so
the bucket that gets created is by construction the bucket that gets checked.
Compose runs it as a one-shot init service (see ``infra/docker-compose.yml``);
it is safe to run repeatedly and on every boot.

It is a *separate* command from the migration one-shot on purpose: object
storage and the relational schema are independent dependencies, so a MinIO
outage must not look like a migration failure in the compose logs.
"""

from __future__ import annotations

from btagent_backend.cli.huntpack import CommandResult


def _ensure_bucket_sync() -> tuple[str, str]:
    """Create the configured bucket if absent. Returns ``(bucket, action)``.

    boto3 is synchronous, so callers run this in a worker thread. ``action`` is
    ``"exists"`` or ``"created"``.
    """
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    from btagent_backend.config import get_settings

    settings = get_settings()
    client = boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        # A few short retries: compose gates this on MinIO's healthcheck, but a
        # just-passed healthcheck can still refuse the first API call.
        config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 3}),
    )
    bucket = settings.s3_bucket

    try:
        client.head_bucket(Bucket=bucket)
        return bucket, "exists"
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        # 404 / NoSuchBucket => create it. Anything else (403 = wrong creds,
        # connection errors) must surface rather than be papered over by a
        # create attempt that will fail with a less obvious message.
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise

    kwargs: dict[str, object] = {"Bucket": bucket}
    # us-east-1 is the only region where S3 rejects an explicit
    # LocationConstraint; MinIO accepts either form.
    if settings.s3_region and settings.s3_region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": settings.s3_region}

    try:
        client.create_bucket(**kwargs)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        # Lost a race with another replica running the same init — that is the
        # desired end state, not an error.
        if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
        return bucket, "exists"

    return bucket, "created"


async def cmd_init_storage() -> CommandResult:
    """``bt init-storage`` — ensure the evidence bucket exists."""
    import asyncio

    from btagent_backend.config import get_settings

    try:
        bucket, action = await asyncio.to_thread(_ensure_bucket_sync)
    except Exception as exc:  # noqa: BLE001 — report, don't traceback at an operator
        endpoint = get_settings().s3_endpoint
        return CommandResult(
            exit_code=1,
            lines=[
                f"could not ensure the evidence bucket at {endpoint}: {exc}",
                "check BTAGENT_S3_ENDPOINT / BTAGENT_S3_ACCESS_KEY / BTAGENT_S3_SECRET_KEY.",
            ],
        )

    verb = "already present" if action == "exists" else "created"
    return CommandResult(
        exit_code=0,
        lines=[f"evidence bucket '{bucket}' {verb} at {get_settings().s3_endpoint}."],
        data={"bucket": bucket, "action": action},
    )
