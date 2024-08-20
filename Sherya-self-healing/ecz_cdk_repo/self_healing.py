from aws_cdk import (
    Stack,
    aws_apigateway as apigateway,
    aws_lambda as _lambda,
    Duration,
    aws_iam as iam,
    CfnOutput,
    aws_ssm as ssm,
        aws_iam
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

        # Define the parameter name for API key ID
        parameter_name = f"/api_gateway/api_key_id"


        # Retrieve the API key ID from SSM Parameter Store
        api_key_id = ssm.StringParameter.value_for_string_parameter(
            self,
            parameter_name
        )

        # Use the retrieved API key ID
        api_key = apigateway.ApiKey.from_api_key_id(
            self, "ExistingApiKey",
            api_key_id=api_key_id
        )

        # API Gateway
        api_gateway = apigateway.RestApi(
            self, 
            f"OcrApiGateway-{environment_type}",
            api_key_source_type=apigateway.ApiKeySourceType.HEADER,
            # disable_execute_api_endpoint=True,
            deploy_options=apigateway.StageOptions(stage_name=environment_type)
        )

        upload = api_gateway.root.add_resource('upload')
        upload_method = upload.add_method(
            "POST",
            integration=apigateway.LambdaIntegration(handler=lambda_function),
            api_key_required=True
        )

        usage_plan = api_gateway.add_usage_plan(
            "Usage Plan",
            name=f"ocr-usage-plan-{environment_type}"
        )
        usage_plan.add_api_key(api_key)
        usage_plan.add_api_stage(stage=api_gateway.deployment_stage)

        # Outputs
        CfnOutput(self, "LambdaFunctionName",
                  value=lambda_function.function_name,
                  description="The name of the Lambda function")

        CfnOutput(self, "DeploymentRegion",
                  value=current_region,
                  description="The region where this stack is deployed")

        CfnOutput(self, "ApiGatewayUrl",
                  value=api_gateway.url,
                  description="The URL of the API Gateway")

        CfnOutput(self, "ApiKeyId",
                  value=api_key_id,
                  description="The ID of the API key")