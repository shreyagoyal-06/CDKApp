#!/usr/bin/env python3
import os

import aws_cdk as cdk

from ecz_cdk_repo.ecz_pipeline_stack import EczPipelineStack

account_num = '913524913171'
aws_region = 'us-west-2'
app = cdk.App()
EczPipelineStack(app, "self-healing-code-app",
                 env=cdk.Environment(account=account_num, region=aws_region))
app.synth()
