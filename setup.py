#!/usr/bin/env python3
import boto3
import json
import zipfile
import io
import os
import time


# --- Helper: prompt with default value ---
def prompt_with_default(prompt_text, default):
    inp = input(f"{prompt_text} (default: {default}): ")
    return inp.strip() if inp.strip() != "" else default


# --- Interactive configuration ---
REGION = "us-east-1"
IAM_ROLE_NAME = prompt_with_default("Enter IAM Role name", "LambdaExecutionRole")
SNS_TOPIC_NAME = prompt_with_default("Enter SNS Topic name", "IAMEventAlertTopic")
EVENT_RULE_NAME = prompt_with_default(
    "Enter EventBridge Rule name", "IAMEventAlertRule"
)
LAMBDA_FUNCTION_NAME = prompt_with_default(
    "Enter Lambda Function name", "IAMEventAlertFunction"
)
EVENTBRIDGE_ROLE_NAME = prompt_with_default(
    "Enter EventBridge Role name", "EventBridgeInvokeLambdaRole"
)
EMAIL_SUBSCRIPTION = prompt_with_default(
    "Enter Email Subscription address", "your-email@example.com"
)
ZIP_FILE_PATH = prompt_with_default(
    "Enter path for the Lambda zip file", "lambda_function.zip"
)
# Lambda handler and runtime are assumed constants:
LAMBDA_HANDLER = "lambda_function.lambda_handler"
LAMBDA_RUNTIME = "python3.13"

# EventBridge rule event pattern (IAM events from CloudTrail)
EVENT_PATTERN = {
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
        "eventSource": ["iam.amazonaws.com"],
        "eventName": [
            "CreateUser",
            "DeleteUser",
            "PutUserPolicy",
            "CreateAccessKey",
            "CreateLoginProfile",
            "UpdateAccessKey",
            "UpdateLoginProfile",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "DeleteUserPolicy",
            "AddUserToGroup",
            "RemoveUserFromGroup",
            "DeactivateMFADevice",
            "DeleteAccessKey",
            "DeleteLoginProfile",
            "CreateRole",
            "AttachRolePolicy",
            "DetachRolePolicy",
            "PutRolePolicy",
            "DeleteRolePolicy",
            "UpdateAssumeRolePolicy",
            "DeleteRole",
            "AttachGroupPolicy",
            "DetachGroupPolicy",
            "CreateGroup",
            "DeleteGroup",
        ],
    },
}

# --- Set up AWS service clients ---
boto3.setup_default_session(region_name=REGION)
iam_client = boto3.client("iam")
sns_client = boto3.client("sns")
lambda_client = boto3.client("lambda")
events_client = boto3.client("events")


# --- 1. Create or get the IAM Role for Lambda ---
def get_or_create_iam_role():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role = iam_client.get_role(RoleName=IAM_ROLE_NAME)
        print(f"IAM Role '{IAM_ROLE_NAME}' exists.")
        use_existing = prompt_with_default("Use existing IAM Role? (Y/n)", "Y")
        if use_existing.lower() != "y":
            print("Exiting – please delete the existing role and rerun to recreate it.")
            exit(1)
        return role["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Creating IAM Role '{IAM_ROLE_NAME}'...")
        role = iam_client.create_role(
            RoleName=IAM_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="IAM Role for Lambda function to handle IAM event alerts",
        )
        role_arn = role["Role"]["Arn"]
        # Attach managed policy for CloudWatch Logs
        iam_client.attach_role_policy(
            RoleName=IAM_ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        # Attach an inline policy for SNS Publish (initially broad; will update later)\n
        sns_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sns:Publish",
                    "Resource": "*",  # Will update to restrict to our topic later
                }
            ],
        }
        iam_client.put_role_policy(
            RoleName=IAM_ROLE_NAME,
            PolicyName="SNSPublishPolicy",
            PolicyDocument=json.dumps(sns_policy),
        )
        time.sleep(10)  # Wait for propagation
        return role_arn


# --- 2. Create or get SNS Topic and ensure email subscription ---
def get_or_create_sns_topic():
    response = sns_client.create_topic(Name=SNS_TOPIC_NAME)
    topic_arn = response["TopicArn"]
    print(f"SNS Topic '{SNS_TOPIC_NAME}' ARN: {topic_arn}")
    return topic_arn


def ensure_sns_subscription(topic_arn):
    subs = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
    for sub in subs.get("Subscriptions", []):
        if sub.get("Protocol") == "email" and sub.get("Endpoint") == EMAIL_SUBSCRIPTION:
            print(f"Email subscription for {EMAIL_SUBSCRIPTION} already exists.")
            return
    print(f"Creating SNS subscription for {EMAIL_SUBSCRIPTION}...")
    sns_client.subscribe(
        TopicArn=topic_arn, Protocol="email", Endpoint=EMAIL_SUBSCRIPTION
    )
    print("Subscription created. Please check your email to confirm.")


def update_sns_publish_policy(role_name, sns_topic_arn):
    # Update inline policy to restrict sns:Publish only to the created SNS topic ARN.
    sns_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sns:Publish", "Resource": sns_topic_arn}
        ],
    }
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="SNSPublishPolicy",
        PolicyDocument=json.dumps(sns_policy),
    )
    print("SNSPublishPolicy updated to restrict publishing to the SNS topic ARN.")


# --- 3. Create or get the IAM Role for EventBridge ---
def get_or_create_eventbridge_role():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role = iam_client.get_role(RoleName=EVENTBRIDGE_ROLE_NAME)
        print(f"EventBridge Role '{EVENTBRIDGE_ROLE_NAME}' exists.")
        use_existing = prompt_with_default("Use existing EventBridge Role? (Y/n)", "Y")
        if use_existing.lower() != "y":
            print("Exiting – please delete the existing role and rerun to recreate it.")
            exit(1)
        return role["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Creating EventBridge Role '{EVENTBRIDGE_ROLE_NAME}'...")
        role = iam_client.create_role(
            RoleName=EVENTBRIDGE_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for EventBridge rule to invoke Lambda",
        )
        role_arn = role["Role"]["Arn"]
        time.sleep(10)
        return role_arn


def update_eventbridge_role_policy(role_name, lambda_function_arn):
    # Update the inline policy for the eventbridge role to allow invoking the specific Lambda function.
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": lambda_function_arn,
            }
        ],
    }
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName="EventBridgeInvokeLambdaPolicy",
        PolicyDocument=json.dumps(policy_document),
    )
    print("EventBridge role policy updated with Lambda invoke permissions.")


# --- 4. Zip Lambda Function Code ---
def zip_directory(source_dir, zip_file_path):
    # Zip only the lambda_function.py file in the current directory
    zip_buffer = io.BytesIO()
    lambda_file = "lambda_function.py"
    file_path = os.path.join(source_dir, lambda_file)
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            file_data = f.read()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(lambda_file, file_data)
        with open(zip_file_path, "wb") as f_out:
            f_out.write(zip_buffer.getvalue())
        print(f"'{lambda_file}' zipped into '{zip_file_path}'.")
    else:
        print(f"'{lambda_file}' not found in '{source_dir}'.")


# --- 5. Create or get Lambda Function ---
def get_or_create_lambda_function(role_arn, topic_arn):
    try:
        response = lambda_client.get_function(FunctionName=LAMBDA_FUNCTION_NAME)
        print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' already exists.")
        use_existing = prompt_with_default("Use existing Lambda function? (Y/n)", "Y")
        if use_existing.lower() != "y":
            print(
                "Exiting – please delete the existing function and rerun to recreate it."
            )
            exit(1)
        return response["Configuration"]["FunctionArn"]
    except lambda_client.exceptions.ResourceNotFoundException:
        print(f"Creating Lambda function '{LAMBDA_FUNCTION_NAME}'...")
        with open(ZIP_FILE_PATH, "rb") as f:
            zipped_code = f.read()
        response = lambda_client.create_function(
            FunctionName=LAMBDA_FUNCTION_NAME,
            Runtime=LAMBDA_RUNTIME,
            Role=role_arn,
            Handler=LAMBDA_HANDLER,
            Code={"ZipFile": zipped_code},
            Description="Lambda function for IAM Event Alerts",
            Timeout=30,
            MemorySize=128,
            Environment={"Variables": {"SNS_TOPIC_ARN": topic_arn}},
            Publish=True,
        )
        time.sleep(10)
        return response["FunctionArn"]


def add_lambda_permission_for_events(function_name):
    statement_id = "AllowEventBridgeInvoke"
    try:
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
        )
        print("Lambda permission for EventBridge added.")
    except lambda_client.exceptions.ResourceConflictException:
        print("Lambda permission for EventBridge already exists.")


# --- 6. Create or get EventBridge Rule ---
def get_or_create_event_rule(lambda_function_arn, eventbridge_role_arn):
    try:
        rule_response = events_client.describe_rule(Name=EVENT_RULE_NAME)
        rule_arn = rule_response["Arn"]
        print(f"EventBridge Rule '{EVENT_RULE_NAME}' already exists.")
    except events_client.exceptions.ResourceNotFoundException:
        print(f"Creating EventBridge Rule '{EVENT_RULE_NAME}'...")
        rule_response = events_client.put_rule(
            Name=EVENT_RULE_NAME,
            EventPattern=json.dumps(EVENT_PATTERN),
            State="ENABLED",
            Description="Triggers Lambda on IAM events via CloudTrail",
        )
        rule_arn = rule_response["RuleArn"]
    targets = events_client.list_targets_by_rule(Rule=EVENT_RULE_NAME)
    target_exists = any(
        t.get("Arn") == lambda_function_arn for t in targets.get("Targets", [])
    )
    if not target_exists:
        print("Adding Lambda function as target to the EventBridge rule...")
        events_client.put_targets(
            Rule=EVENT_RULE_NAME,
            Targets=[
                {"Id": "1", "Arn": lambda_function_arn, "RoleArn": eventbridge_role_arn}
            ],
        )
    else:
        print("Lambda function target already exists for the EventBridge rule.")
    return rule_arn


# --- Main Execution ---
def main():
    print("Starting interactive AWS resource setup in region", REGION)
    role_arn = get_or_create_iam_role()
    topic_arn = get_or_create_sns_topic()
    ensure_sns_subscription(topic_arn)
    update_sns_publish_policy(IAM_ROLE_NAME, topic_arn)

    # Create a role for EventBridge
    eventbridge_role_arn = get_or_create_eventbridge_role()

    # Zip the contents of the current directory into the ZIP file
    zip_directory(".", ZIP_FILE_PATH)
    lambda_function_arn = get_or_create_lambda_function(role_arn, topic_arn)
    add_lambda_permission_for_events(LAMBDA_FUNCTION_NAME)

    # Now update the EventBridge role's inline policy with the specific Lambda function ARN
    update_eventbridge_role_policy(EVENTBRIDGE_ROLE_NAME, lambda_function_arn)

    get_or_create_event_rule(lambda_function_arn, eventbridge_role_arn)
    print("Setup completed successfully in region", REGION)


if __name__ == "__main__":
    main()
