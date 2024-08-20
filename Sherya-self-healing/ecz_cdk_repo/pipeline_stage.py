from .self_healing import SelfHealing
from aws_cdk import (
    Stage
)
from constructs import Construct
class self_heal_Stage(Stage):
    def __init__(self, scope: Construct, id: str, environment_type: str, account: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        service = SelfHealing(
            self, 
            f'self-healing-{kwargs["env"].region}', 
            environment_type=environment_type,
            account=account,
            env=kwargs["env"]
        )