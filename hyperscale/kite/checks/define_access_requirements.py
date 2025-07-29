from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class DefineAccessRequirementsCheck:
    def __init__(self):
        self.check_id = "define-access-requirements"
        self.check_name = "Define Access Requirements"

    @property
    def question(self) -> str:
        return (
            "Is there a clear definition of who or what should have access to each "
            "component?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is a clear definition of who or what "
            "should have access to each resource or component."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider whether there is a clear definition of who or what should have "
            "access to each resource or component?\n\n"
            "This could be in the form of a simple table similar to the following:\n\n"
            "|--------------------------|---------------------------------------------|--------------|\n"
            "| Who / what               | Resource / component                        | Access       |\n"  # noqa E501
            "|--------------------------|---------------------------------------------|--------------|\n"
            "| MyApp ECS tasks          | All objects in the 'my-app-media' S3 bucket | read         |\n"  # noqa E501
            "| MyApp ECS tasks          | my-app dynamodb table                       | read / write |\n"  # noqa E501
            "| MyApp ECS task exec      | my-app/secret-key SM secret                 | read         |\n"  # noqa E501
            "| MyApp secrets admin user | my-app/secret-key SM secret                 | read / write |\n"  # noqa E501
            "|---------------------------------------------------------------------------------------|\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
