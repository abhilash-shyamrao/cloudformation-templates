from troposphere import Template, Ref, GetAtt, Join, Sub, Output
from troposphere.iam import Role, Policy
from troposphere.awslambda import Function, Code
from troposphere.stepfunctions import StateMachine

t = Template()
t.add_description("CloudFormation Template to create a Step Functions State Machine with Lambda integration.")

# Lambda execution role
lambda_execution_role = t.add_resource(
    Role(
        "LambdaExecutionRole",
        AssumeRolePolicyDocument={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["lambda.amazonaws.com"]},
                "Action": ["sts:AssumeRole"]
            }]
        },
        Policies=[
            Policy(
                PolicyName="LambdaLogging",
                PolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": "arn:aws:logs:*:*:*"
                    }]
                }
            )
        ]
    )
)

# Lambda function
lambda_function = t.add_resource(
    Function(
        "HelloWorldFunction",
        Code=Code(
            ZipFile=Join("\n", [
                "def handler(event, context):",
                "    return 'Hello World from Lambda!'"
            ])
        ),
        Handler="index.handler",
        Role=GetAtt(lambda_execution_role, "Arn"),
        Runtime="python3.8"
    )
)

# Step Functions execution role
step_functions_execution_role = t.add_resource(
    Role(
        "StepFunctionsExecutionRole",
        AssumeRolePolicyDocument={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["states.amazonaws.com"]},
                "Action": ["sts:AssumeRole"]
            }]
        },
        Policies=[
            Policy(
                PolicyName="StepFunctionsLambdaInvocation",
                PolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        "Resource": GetAtt(lambda_function, "Arn")
                    }]
                }
            )
        ]
    )
)

# Step Functions state machine
state_machine = t.add_resource(
    StateMachine(
        "StepFunction",
        DefinitionString=Sub(
            '{"Comment": "A simple AWS Step Functions state machine that executes a Lambda function.",'
            ' "StartAt": "HelloWorld",'
            ' "States": {'
            '   "HelloWorld": {'
            '     "Type": "Task",'
            '     "Resource": "${HelloWorldFunctionArn}",'
            '     "End": true'
            '   }'
            ' }}',
            HelloWorldFunctionArn=GetAtt(lambda_function, "Arn")
        ),
        RoleArn=GetAtt(step_functions_execution_role, "Arn")
    )
)

# Output
t.add_output(Output(
    "StateMachineArn",
    Description="The ARN of the State Machine",
    Value=Ref(state_machine)
))

print(t.to_json())
