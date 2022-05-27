# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM --platform=linux/amd64 public.ecr.aws/lambda/python:3.8
LABEL name=lambda/python/clamav
LABEL version=1.0

ARG CACHE_DATE=1
RUN yum update -y
RUN yum install -y amazon-linux-extras
RUN PYTHON=python2 amazon-linux-extras install epel
RUN yum -y install clamav clamd p7zip
RUN yum clean all
RUN yum -y install gcc python-devel krb5-devel krb5-workstation python-devel
RUN pip3 install --no-cache-dir cffi awslambdaric boto3 requests aws-lambda-powertools smbprotocol[kerberos]
RUN ln -s /etc/freshclam.conf /tmp/freshclam.conf

COPY clamd.conf /etc/clamd.conf
COPY lambda.py /var/task/lambda.py
ENTRYPOINT [ "/var/lang/bin/python3", "-m", "awslambdaric" ]
CMD [ "lambda.lambda_handler" ]