from aws_cdk import (
    Stack,
    aws_apigateway as apigateway,
    aws_lambda as _lambda,
    Duration,
    aws_iam as iam,
    CfnOutput,
    aws_ssm as ssm,
    aws_iam  # Duplicate import
)
from constructs import Construct

class SelfHealing(Stack):

    def __init__(self, scope: Construct, construct_id: str, environment_type: str, account: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        current_region = self.region
        default_region = 'us-west-2'

        # Lambda Function
        lambda_function = _lambda.Function(
            self, 'lambda_ocr_function',
            runtime=_lambda.Runtime.PYTHON_3_11,
            architecture=_lambda.Architecture.ARM_64,
            code=_lambda.Code.from_asset('backend/lambda/self_healing/'),
            handler='lambda_function.lambda_handler',
            function_name=f'self-healing-{environment_type}-{current_region}',

            environment={
                'environment_type': environment_type
            },
            memory_size=3008,

            timeout=Duration.minutes(2)
        )

       