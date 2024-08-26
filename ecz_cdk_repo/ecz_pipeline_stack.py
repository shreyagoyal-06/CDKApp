from aws_cdk import Stack, pipelines, aws_iam as iam, aws_logs as logs, Environment
from constructs import Construct
from ecz_cdk_repo.pipeline_stage import self_heal_Stage
import aws_cdk as cdk

class EczPipelineStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # GitHub repository information
        owner = "shreyagoyal-06"
        repo = "CDKApp".  
        branch = "main"  # or your default branch name

        # Create a GitHub source action
        source = pipelines.CodePipelineSource.connection(
            f"{owner}/{repo}",
            branch,
            connection_arn="arn:aws:codeconnections:us-west-2:913524913171:connection/0e6304b1-88f7-4886-8208-1de75317c190"  # Replace with your connection ARN
        )

         Create a CloudWatch log group
        log_group = logs.LogGroup(
            self,
            "PipelineLogGroup",
            log_group_name="/aws/codepipeline/self-heal-app-pipeline",
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create the IAM policy for CloudWatch Logs
        cloudwatch_policy = iam.PolicyStatement(
            actions=["logs:PutLogEvents", "logs:CreateLogStream"],
            resources=[log_group.log_group_arn]
        )

        # Create a custom shell script to run commands and log errors
        error_logging_script = """
            set -e
            log_error() {
                error_message="error: $1"
                aws logs put-log-events --log-group-name /aws/codepipeline/self-heal-app-pipeline --log-stream-name pipeline-errors --log-events timestamp=$(date +%s%3N),message="$error_message"
            }

            npm install -g aws-cdk@2 || { log_error "Failed to install aws-cdk: $?"; exit 1; }
            pip install -r requirements.txt || { log_error "Failed to install requirements: $?"; exit 1; }
            echo "Deploying application using AWS CDK"
            cdk synth 2>&1 | tee synth_output.log || {
                error_output=$(cat synth_output.log)
                log_error "CDK synth failed: $error_output"
                exit 1
            }
        """

        pipeline = pipelines.CodePipeline(
            self,
            "self-heal-app",
            pipeline_name="self-heal-app-pipeline",
            cross_account_keys=True,
            synth=pipelines.ShellStep(
                "Synth",
                input=source,
                commands=[error_logging_script],
            ),
            synth_code_build_defaults=pipelines.CodeBuildOptions(
                role_policy=[cloudwatch_policy]
            )
        )

        envs = {"dev": "913524913171"}
        regions = ["us-west-2"]

        for environment_type, account in envs.items():
            wave = pipeline.add_wave(f"{environment_type}-deployment-parallel")

            if environment_type != "dev":
                wave.add_pre(pipelines.ManualApprovalStep(f"promote-to-{environment_type}"))

            for region in regions:
                deploy_apigateway = self_heal_Stage(
                    self,
                    f"{environment_type}-{region}-deploy",
                    environment_type=environment_type,
                    account=account,
                    env=cdk.Environment(account=account, region=region)
                )
                wave.add_stage(deploy_apigateway)
