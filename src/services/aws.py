from os import getenv
from enum import Enum
from typing import Any

import boto3
from retry.api import retry
from botocore.exceptions import (
    CapacityNotAvailableError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

import internals

STORE_BUCKET = getenv("STORE_BUCKET", "trivialscan-dashboard-store")
s3_client = boto3.client(service_name="s3")


class StorageClass(str, Enum):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"


@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def object_exists(file_path: str, bucket_name: str = STORE_BUCKET, **kwargs):
    try:
        content = s3_client.head_object(Bucket=bucket_name, Key=file_path, **kwargs)
        return content.get("ResponseMetadata", None) is not None
    except ClientError as err:
        internals.logger.debug(err, exc_info=True)
    return False


@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def list_s3(prefix_key: str, bucket_name: str = STORE_BUCKET) -> list[str]:
    """
    params:
    - bucket_name: s3 bucket with target contents
    - prefix_key: pattern to match in s3
    """
    internals.logger.info(f"requesting bucket {bucket_name} key prefix {prefix_key}")
    keys = []
    next_token = ""
    base_kwargs = {
        "Bucket": bucket_name,
        "Prefix": prefix_key,
    }
    base_kwargs.update()
    while next_token is not None:
        args = base_kwargs.copy()
        if next_token != "":
            args.update({"ContinuationToken": next_token})
        try:
            results = s3_client.list_objects_v2(**args)

        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchBucket":  # type: ignore
                internals.logger.error(
                    f"The requested bucket {bucket_name} was not found"
                )
            elif err.response["Error"]["Code"] == "InvalidObjectState":  # type: ignore
                internals.logger.error(f"The request was invalid due to: {err}")
            elif err.response["Error"]["Code"] == "InvalidParameterException":  # type: ignore
                internals.logger.error(f"The request had invalid params: {err}")
            else:
                internals.logger.exception(err)
            return []
        for item in results.get("Contents", []):
            k = item["Key"]  # type: ignore
            if k[-1] != "/":
                keys.append(k)
        next_token = results.get("NextContinuationToken")

    return keys


@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def get_s3(
    path_key: str, bucket_name: str = STORE_BUCKET, default: Any = None, **kwargs
) -> Any:
    internals.logger.info(f"requesting bucket {bucket_name} object key {path_key}")
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=path_key, **kwargs)
        return response["Body"].read().decode("utf8")

    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":  # type: ignore
            internals.logger.warning(
                f"The requested bucket {bucket_name} object key {path_key} was not found"
            )
        elif err.response["Error"]["Code"] == "InvalidObjectState":  # type: ignore
            internals.logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "InvalidParameterException":  # type: ignore
            internals.logger.warning(f"The request had invalid params: {err}")
        else:
            internals.logger.exception(err)
    return default


@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def store_s3(
    path_key: str,
    value: str,
    bucket_name: str = STORE_BUCKET,
    storage_class: StorageClass = StorageClass.STANDARD_IA,
    **kwargs,
) -> bool:
    internals.logger.info(f"store_s3 {path_key}")
    internals.logger.debug(f"store_s3 {value}")
    try:
        response = s3_client.put_object(
            Bucket=bucket_name,
            Key=path_key,
            Body=value,
            StorageClass=str(storage_class.name),  # type: ignore
            **kwargs,
        )
        return (
            False
            if not isinstance(response, dict)
            else response.get("ETag") is not None
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ParameterAlreadyExists":  # type: ignore
            internals.logger.warning(
                f"The object bucket {bucket_name} key {path_key} already exists"
            )
        elif err.response["Error"]["Code"] == "InternalServerError":  # type: ignore
            internals.logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "TooManyUpdates":  # type: ignore
            internals.logger.warning(err, exc_info=True)
            raise RuntimeError(
                "Please throttle your requests to continue using this service"
            ) from err
        elif err.response["Error"]["Code"] == "ParameterLimitExceeded":  # type: ignore
            internals.logger.warning(err, exc_info=True)
            raise RuntimeError(
                "Platform is exhausted and unable to respond, please try again soon"
            ) from err
        else:
            internals.logger.exception(err)
    return False
