# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from posixpath import join
import boto3
import botocore
import glob
import json
import logging
import os
import pwd
import subprocess
import shutil
import base64
import json
import gzip
import io
import uuid
from urllib.parse import unquote_plus
import xml.etree.ElementTree as ET
from aws_lambda_powertools import Logger, Metrics

try:
    from gssapi.raw import inquire_sec_context_by_oid
    print("python-gssapi extension is available")
except ImportError as exc:
    print("python-gssapi extension is not available: %s" % str(exc))

from smbclient import (
    open_file,
    stat
)

logger = Logger()
metrics = Metrics()

s3_resource = boto3.resource("s3")
s3_client = boto3.client("s3")

dynamo_client = boto3.client("dynamodb")
dynamo_resource = boto3.resource("dynamodb")

INPROGRESS = "IN PROGRESS"
CLEAN = "CLEAN"
INFECTED = "INFECTED"
ERROR = "ERROR"
SKIP = "N/A"

MAX_BYTES = 4000000000


class ClamAVException(Exception):
    """Raise when ClamAV returns an unexpected exit code"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class ArchiveException(Exception):
    """Raise when 7za exits with an unexpected code"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


class FileTooBigException(Exception):
    """Raise when file(s) is/are too large for ClamAV to scan"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


@metrics.log_metrics(capture_cold_start_metric=True)
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    logger.info(json.dumps(event))

    # bucket_info = event["Records"][0]["s3"]
    # input_bucket = bucket_info["bucket"]["name"]
    # input_key = unquote_plus(bucket_info["object"]["key"])

    data = event["awslogs"]["data"]

    log_object = json.load(
        io.BytesIO(
            gzip.decompress(
                base64.b64decode(data)
            )
        )
    )

    table_name = os.environ["TABLE_NAME"]

    for event in log_object["logEvents"]:
        el = ET.fromstring(event["message"])
        operation = el.find("./EventData/Data[@Name='operation']").text
        object_name = el.find("./EventData/Data[@Name='ObjectName']").text
        location_dns_name = el.find(
            "./EventData/Data[@Name='locationDnsName']").text
        source = el.find("./EventData/Data[@Name='source']").text

    # summary = ""

        summary = {}
        if not object_name.endswith("/"):
            mount_path = os.environ["EFS_MOUNT_PATH"]
            definitions_path = f"{mount_path}/{os.environ['EFS_DEF_PATH']}"
            payload_path = f"{mount_path}/{context.aws_request_id}"
            tmp_path = f"{payload_path}-tmp"
            set_status(source, object_name, INPROGRESS)
            create_dir(source, object_name, payload_path)
            create_dir(source, object_name, tmp_path)
            download_object(location_dns_name, source,
                            object_name, payload_path)
            expand_if_large_archive(
                source,
                object_name,
                payload_path,
                stat(f"//{location_dns_name}{object_name}",
                     username=os.environ["SMB_USERNAME"], password=os.environ["SMB_PASSWORD"]).st_size
            )
            create_dir(source, object_name, definitions_path)
            freshclam_update(
                source, object_name, payload_path, definitions_path
            )
            summary = scan(
                source, object_name, payload_path, definitions_path, tmp_path
            )
            delete(payload_path)
            delete(tmp_path)
        else:
            summary = {
                "source": "serverless-clamscan",
                "input_bucket": source,
                "input_key": object_name,
                "status": SKIP,
                "message": "S3 Event trigger was for a non-file object",
            }
    logger.info(summary)
    return summary


def set_status(source, object_name, status):
    """Set the scan-status tag of the S3 Object"""
    # old_tags = {}
    # try:
    #     response = s3_client.get_object_tagging(Bucket=bucket, Key=key)
    #     old_tags = {i["Key"]: i["Value"] for i in response["TagSet"]}
    # except botocore.exceptions.ClientError as e:
    #     logger.debug(e.response["Error"]["Message"])
    # new_tags = {"scan-status": status}
    # tags = {**old_tags, **new_tags}
    # s3_client.put_object_tagging(
    #     Bucket=bucket,
    #     Key=key,
    #     Tagging={
    #         "TagSet": [
    #             {"Key": str(k), "Value": str(v)} for k, v in tags.items()
    #         ]
    #     },
    # )

    try:
        dynamo_client.update_item(
            TableName=os.environ["TABLE_NAME"],
            Item={
                'source': source,
                'object_name': object_name,
                'status': status,
            }
        )
    except botocore.exceptions.ClientError as e:
        logger.debug(e.response["Error"]["Message"])
    metrics.add_metric(name=status, unit="Count", value=1)


def create_dir(source, object_name, download_path):
    """Creates a directory at the specified location
    if it does not already exists"""
    sub_dir = os.path.dirname(object_name)
    full_path = download_path
    if len(sub_dir) > 0:
        full_path = os.path.join(full_path, sub_dir)
    if not os.path.exists(full_path):
        try:
            os.makedirs(full_path, exist_ok=True)
        except OSError as e:
            report_failure(source, object_name, download_path, str(e))


def download_object(location_dns_name, source, object_name, download_path):
    """Downloads the specified file from S3 to EFS"""

    try:
        with open_file(f"""\\{location_dns_name}\{object_name}""", username=os.environ["SMB_USERNAME"], password=os.environ["SMB_PASSWORD"]) as fd:
            with open(os.path.join(download_path, object_name), "wb") as f:
                f.write(fd.read())
    except Exception as e:
        report_failure(
            source,
            object_name,
            download_path,
            e.response["Error"]["Message"],
        )

    # try:
    #     s3_resource.Bucket(input_bucket).download_file(
    #         input_key, f"{download_path}/{input_key}"
    #     )
    # except botocore.exceptions.ClientError as e:
    #     report_failure(
    #         input_bucket,
    #         input_key,
    #         download_path,
    #         e.response["Error"]["Message"],
    #     )


def expand_if_large_archive(source, object_name, download_path, byte_size):
    """Expand the file if it is an archival type and larger than ClamAV Max Size"""
    if byte_size > MAX_BYTES:
        file_name = f"{download_path}/{object_name}"
        try:
            command = ["7za", "x", "-y", f"{file_name}", f"-o{download_path}"]
            archive_summary = subprocess.run(
                command,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
            )
            if archive_summary.returncode not in [0, 1]:
                raise ArchiveException(
                    f"7za exited with unexpected code: {archive_summary.returncode}."
                )
            delete(download_path, object_name)
            large_file_list = []
            for root, dirs, files in os.walk(download_path, topdown=False):
                for name in files:
                    size = os.path.getsize(os.path.join(root, name))
                    if size > MAX_BYTES:
                        large_file_list.append(name)
            if large_file_list:
                raise FileTooBigException(
                    f"Archive {object_name} contains files {large_file_list} "
                    f"which are at greater than ClamAV max of {MAX_BYTES} bytes"
                )
        except subprocess.CalledProcessError as e:
            report_failure(
                source, object_name, download_path, str(e.stderr)
            )
        except ArchiveException as e:
            report_failure(source, object_name, download_path, e.message)
        except FileTooBigException as e:
            report_failure(source, object_name, download_path, e.message)
    else:
        return


def freshclam_update(input_bucket, input_key, download_path, definitions_path):
    """Points freshclam to the local database files and the S3 Definitions bucket.
    Creates the database path on EFS if it does not already exist"""
    conf = "/tmp/freshclam.conf"
    # will already exist when Lambdas are running in same execution context
    if not os.path.exists(conf):
        with open(conf, "a") as f:
            f.write(f"\nPrivateMirror {os.environ['DEFS_URL']}")
    try:
        command = [
            "freshclam",
            f"--config-file={conf}",
            "--stdout",
            "-u",
            f"{pwd.getpwuid(os.getuid()).pw_name}",
            f"--datadir={definitions_path}",
        ]
        update_summary = subprocess.run(
            command,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
        )
        if update_summary.returncode != 0:
            raise ClamAVException(
                f"FreshClam exited with unexpected code: {update_summary.returncode}"
                f"\nOutput: {update_summary.stdout.decode('utf-8')}"
            )
    except subprocess.CalledProcessError as e:
        report_failure(input_bucket, input_key, download_path, str(e.stderr))
    except ClamAVException as e:
        report_failure(input_bucket, input_key, download_path, e.message)
    return


def scan(input_bucket, input_key, download_path, definitions_path, tmp_path):
    """Scans the object from S3"""
    # Max file size support by ClamAV
    try:
        command = [
            "clamscan",
            "-v",
            "--stdout",
            f"--max-filesize={MAX_BYTES}",
            f"--max-scansize={MAX_BYTES}",
            f"--database={definitions_path}",
            "-r",
            f"--tempdir={tmp_path}",
            f"{download_path}",
        ]
        scan_summary = subprocess.run(
            command,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
        )
        status = ""
        if scan_summary.returncode == 0:
            status = CLEAN
        elif scan_summary.returncode == 1:
            status = INFECTED
        else:
            raise ClamAVException(
                f"ClamAV exited with unexpected code: {scan_summary.returncode}."
                f"\nOutput: {scan_summary.stdout.decode('utf-8')}"
            )
        set_status(input_bucket, input_key, status)
        return {
            "source": "serverless-clamscan",
            "input_bucket": input_bucket,
            "input_key": input_key,
            "status": status,
            "message": scan_summary.stdout.decode("utf-8"),
        }
    except subprocess.CalledProcessError as e:
        report_failure(input_bucket, input_key, download_path, str(e.stderr))
    except ClamAVException as e:
        report_failure(input_bucket, input_key, download_path, e.message)


def delete(download_path, input_key=None):
    """Deletes the file/folder from the EFS File System"""
    if input_key:
        file = f"{download_path}/{input_key}"
        if os.path.exists(file):
            os.remove(file)
    else:
        for obj in glob.glob(os.path.join(download_path, "*")):
            if os.path.isdir(obj):
                shutil.rmtree(obj)
            else:
                os.remove(obj)


def report_failure(input_bucket, input_key, download_path, message):
    """Set the S3 object tag to ERROR if scan function fails"""
    set_status(input_bucket, input_key, ERROR)
    delete(download_path)
    exception_json = {
        "source": "serverless-clamscan",
        "input_bucket": input_bucket,
        "input_key": input_key,
        "status": ERROR,
        "message": message,
    }
    raise Exception(json.dumps(exception_json))
