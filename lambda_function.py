import boto3
import os

# Initialize SNS client
sns = boto3.client("sns")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")

# Dictionary of critical IAM events and their security implications
EVENT_TYPE_DESCRIPTIONS = {
    # User-related events
    "CreateUser": "Creation of new IAM user. Monitor for unauthorized account creation.",
    "DeleteUser": "Deletion of IAM user. Could indicate account compromise or sabotage.",
    "CreateAccessKey": "New programmatic access key created. Risk of credential exposure.",
    "DeleteAccessKey": "Access key deleted. Could disrupt services or hide malicious activity.",
    "CreateLoginProfile": "Console access enabled for user. Verify password setup legitimacy.",
    "UpdateLoginProfile": "Console password changed. Potential password reset attack.",
    "DeleteLoginProfile": "Console access removed. May lock out legitimate users.",
    
    # Policy-related events
    "PutUserPolicy": "Inline policy added/modified for user. Check for excessive permissions.",
    "DeleteUserPolicy": "Inline policy removed from user. Verify intentional permission change.",
    "AttachUserPolicy": "Managed policy attached to user. Potential privilege escalation.",
    "DetachUserPolicy": "Managed policy removed from user. Verify intentional change.",
    
    # Group-related events
    "AddUserToGroup": "User added to group. Could grant indirect permissions.",
    "RemoveUserFromGroup": "User removed from group. Verify intentional membership change.",
    
    # MFA events
    "DeactivateMFADevice": "MFA disabled for user. Critical security reduction!",
    
    # Role-related events
    "CreateRole": "New IAM role created. Verify permissions and trust policy.",
    "DeleteRole": "IAM role deleted. May disrupt services or erase evidence.",
    "AttachRolePolicy": "Policy attached to role. Verify for privilege escalation.",
    "DetachRolePolicy": "Policy detached from role. Verify intentional change.",
    "PutRolePolicy": "Inline policy added/modified for role. Check permissions.",
    "UpdateAssumeRolePolicy": "Role trust policy modified. High risk of cross-account abuse!",
    
    # Group management
    "CreateGroup": "New IAM group created. Verify group policy intentions.",
    "DeleteGroup": "IAM group deleted. May impact access controls.",
    "AttachGroupPolicy": "Policy attached to group. Impacts all group members.",
}


EVENT_SEVERITY = {
    # User Events
    "CreateUser": "HIGH",
    "DeleteUser": "CRITICAL",
    "CreateAccessKey": "HIGH",
    "DeleteAccessKey": "MEDIUM",
    "CreateLoginProfile": "HIGH",
    "UpdateLoginProfile": "HIGH",
    "DeleteLoginProfile": "HIGH",
    "PutUserPolicy": "HIGH",
    "DeleteUserPolicy": "MEDIUM",
    "AttachUserPolicy": "HIGH",
    "DetachUserPolicy": "MEDIUM",
    "AddUserToGroup": "MEDIUM",
    "RemoveUserFromGroup": "MEDIUM",
    "DeactivateMFADevice": "CRITICAL",
    
    # Role Events
    "CreateRole": "HIGH",
    "DeleteRole": "CRITICAL",
    "AttachRolePolicy": "HIGH",
    "DetachRolePolicy": "MEDIUM",
    "PutRolePolicy": "HIGH",
    "DeleteRolePolicy": "MEDIUM",
    "UpdateAssumeRolePolicy": "CRITICAL",
    
    # Group Events
    "CreateGroup": "MEDIUM",
    "DeleteGroup": "MEDIUM",
    "AttachGroupPolicy": "HIGH",
    
    # Account Actions
    "UpdateAccountPasswordPolicy": "HIGH",
    "DeleteAccountPasswordPolicy": "CRITICAL"
}

# In format_iam_alert() function:


def format_iam_alert(event):
    """Formats IAM event data into a readable alert message with event descriptions."""
    user_identity = event.get("userIdentity", {})
    event_time = event.get("eventTime", "N/A")
    event_name = event.get("eventName", "N/A")
    aws_region = event.get("awsRegion", "N/A")
    source_ip = event.get("sourceIPAddress", "N/A")
    account_id = event.get("recipientAccountId", "N/A")
    mfa_authenticated = user_identity.get("sessionContext", {})\
                                    .get("attributes", {})\
                                    .get("mfaAuthenticated", "false")
    severity = EVENT_SEVERITY.get(event_name, "UNKNOWN")
    # Add event type description
    event_name = event.get("eventName", "N/A")
    description = EVENT_TYPE_DESCRIPTIONS.get(event_name, 
        "Security impact: This IAM operation could affect access controls or permissions.")
    
    message = "🚨 IAM EVENT ALERT 🚨\n"
    message += "========================================\n"
    message += "⏰ Event Time: " + event_time + "\n"
    message += "🌍 Region: " + aws_region + "\n"
    message += "📦 AWS Account: " + account_id + "\n"
    message += "🆔 Event ID: " + event.get("eventID", "N/A") + "\n"
    message += "========================================\n\n"
    
    message += "🔹 EVENT DETAILS\n"
    message += "   🔧 Event Name: " + event_name + "\n"
    message += f"   📖 Description: {description}\n"  # <-- Added description line
    message += f"   🚩 Severity: {severity}\n"
    message += "   📡 Event Source: " + event.get("eventSource", "N/A") + "\n\n"
    
    message += "🔹 USER DETAILS\n"
    message += "   👤 User Name: " + str(user_identity.get("userName", "Unknown")) + "\n"
    message += "   🆔 User ARN: " + user_identity.get("arn", "N/A") + "\n"
    message += "   🏦 Account ID: " + user_identity.get("accountId", "N/A") + "\n"
    message += "   🔐 MFA Enabled: " + mfa_authenticated + "\n\n"
    
    message += "🔹 SECURITY INFO\n"
    message += "   🌐 Source IP: " + source_ip + "\n"
    message += "========================================\n"
    
    # Event-specific sections
    if event_name == "CreateUser":
        new_user = event.get("responseElements", {}).get("user", {})
        message += "🔹 CREATED USER DETAILS\n"
        message += "   👤 User Name: " + new_user.get("userName", "N/A") + "\n"
        message += "   🆔 User ID: " + new_user.get("userId", "N/A") + "\n"
        message += "   🔗 User ARN: " + new_user.get("arn", "N/A") + "\n"
        message += "   📅 Creation Date: " + new_user.get("createDate", "N/A") + "\n"
    elif event_name == "DeleteUser":
        request_params = event.get("requestParameters", {})
        deleted_user = request_params.get("userName", "N/A")
        message += "🔹 DELETED USER DETAILS\n"
        message += "   👤 Deleted User: " + deleted_user + "\n"
    elif event_name == "PutUserPolicy":
        request_params = event.get("requestParameters", {})
        affected_user = request_params.get("userName", "N/A")
        policy_name = request_params.get("policyName", "N/A")
        policy_document = request_params.get("policyDocument", "N/A")
        truncated_policy = (policy_document if len(policy_document) <= 200 
                            else policy_document[:200] + "... (truncated)")
        message += "🔹 PUT USER POLICY DETAILS\n"
        message += "   👤 Affected User: " + affected_user + "\n"
        message += "   📝 Policy Name: " + policy_name + "\n"
        message += "   📄 Policy Document: " + truncated_policy + "\n"
    elif event_name == "CreateAccessKey":
        access_key_info = event.get("responseElements", {}).get("accessKey", {})
        message += "🔹 CREATE ACCESS KEY DETAILS\n"
        message += "   👤 Affected User: " + access_key_info.get("userName", "N/A") + "\n"
        message += "   🔑 Access Key ID: " + access_key_info.get("accessKeyId", "N/A") + "\n"
        message += "   ⚡ Status: " + access_key_info.get("status", "N/A") + "\n"
        message += "   📅 Creation Date: " + access_key_info.get("createDate", "N/A") + "\n"
    elif event_name == "CreateLoginProfile":
        login_profile = event.get("responseElements", {}).get("loginProfile", {})
        message += "🔹 CREATE LOGIN PROFILE DETAILS\n"
        message += "   👤 Affected User: " + login_profile.get("userName", "N/A") + "\n"
        message += "   📅 Creation Date: " + login_profile.get("createDate", "N/A") + "\n"
        message += "   🔄 Password Reset Required: " + str(login_profile.get("passwordResetRequired", "N/A")) + "\n"
    elif event_name == "UpdateAccessKey":
        req_params = event.get("requestParameters", {})
        affected_user = req_params.get("userName", "N/A")
        access_key_id = req_params.get("accessKeyId", "N/A")
        new_status = req_params.get("status", "N/A")
        message += "🔹 UPDATE ACCESS KEY DETAILS\n"
        message += "   👤 Affected User: " + affected_user + "\n"
        message += "   🔑 Access Key ID: " + access_key_id + "\n"
        message += "   ⚡ New Status: " + new_status + "\n"
    elif event_name == "UpdateLoginProfile":
        req_params = event.get("requestParameters", {})
        target_user = req_params.get("userName", "N/A")
        pwd_reset_required = req_params.get("passwordResetRequired", "N/A")
        message += "🔹 UPDATE LOGIN PROFILE DETAILS\n"
        message += "   👤 Affected User: " + target_user + "\n"
        message += "   🔄 Password Reset Required: " + str(pwd_reset_required) + "\n"
    elif event_name == "AttachUserPolicy":
        req_params = event.get("requestParameters", {})
        affected_user = req_params.get("userName", "N/A")
        policy_arn = req_params.get("policyArn", "N/A")
        message += "🔹 ATTACH USER POLICY DETAILS\n"
        message += "   👤 Affected User: " + affected_user + "\n"
        message += "   📝 Policy ARN: " + policy_arn + "\n"
    elif event_name == "DetachUserPolicy":
        req_params = event.get("requestParameters", {})
        affected_user = req_params.get("userName", "N/A")
        policy_arn = req_params.get("policyArn", "N/A")
        message += "🔹 DETACH USER POLICY DETAILS\n"
        message += "   👤 Affected User: " + affected_user + "\n"
        message += "   📝 Policy ARN: " + policy_arn + "\n"
    elif event_name == "DeleteUserPolicy":
        request_params = event.get("requestParameters", {})
        affected_user = request_params.get("userName", "N/A")
        policy_name = request_params.get("policyName", "N/A")
        message += "🔹 DELETE USER POLICY DETAILS\n"
        message += "   👤 Affected User: " + affected_user + "\n"
        message += "   📝 Policy Name: " + policy_name + "\n"
    elif event_name == "AddUserToGroup":
        req_params = event.get("requestParameters", {})
        added_user = req_params.get("userName", "N/A")
        group_name = req_params.get("groupName", "N/A")
        message += "🔹 ADD USER TO GROUP DETAILS\n"
        message += "   👤 Added User: " + added_user + "\n"
        message += "   👥 Group Name: " + group_name + "\n"
    elif event_name == "RemoveUserFromGroup":
        req_params = event.get("requestParameters", {})
        removed_user = req_params.get("userName", "N/A")
        group_name = req_params.get("groupName", "N/A")
        message += "🔹 REMOVE USER FROM GROUP DETAILS\n"
        message += "   👤 Removed User: " + removed_user + "\n"
        message += "   👥 Group Name: " + group_name + "\n"
    elif event_name == "DeactivateMFADevice":
        req_params = event.get("requestParameters", {})
        user_name = req_params.get("userName", "N/A")
        serial_number = req_params.get("serialNumber", "N/A")
        message += "🔹 DEACTIVATE MFA DEVICE DETAILS\n"
        message += "   👤 User Name: " + user_name + "\n"
        message += "   🔑 Serial Number: " + serial_number + "\n"
    elif event_name == "DeleteAccessKey":
        req_params = event.get("requestParameters", {})
        affected_user = req_params.get("userName", "N/A")
        access_key_id = req_params.get("accessKeyId", "N/A")
        message += "🔹 DELETE ACCESS KEY DETAILS\n"
        message += "   👤 Affected User: " + affected_user + "\n"
        message += "   🔑 Access Key ID: " + access_key_id + "\n"
    elif event_name == "DeleteLoginProfile":
        req_params = event.get("requestParameters", {})
        deleted_user = req_params.get("userName", "N/A")
        message += "🔹 DELETE LOGIN PROFILE DETAILS\n"
        message += "   👤 Deleted User: " + deleted_user + "\n"
    elif event_name == "CreateRole":
        role_info = event.get("responseElements", {}).get("role", {})
        role_name = role_info.get("roleName", "N/A")
        role_id = role_info.get("roleId", "N/A")
        role_arn = role_info.get("arn", "N/A")
        create_date = role_info.get("createDate", "N/A")
        message += "🔹 CREATED ROLE DETAILS\n"
        message += "   👤 Role Name: " + role_name + "\n"
        message += "   🆔 Role ID: " + role_id + "\n"
        message += "   🔗 Role ARN: " + role_arn + "\n"
        message += "   📅 Creation Date: " + create_date + "\n"
    elif event_name == "AttachRolePolicy":
        req_params = event.get("requestParameters", {})
        role_name = req_params.get("roleName", "N/A")
        policy_arn = req_params.get("policyArn", "N/A")
        message += "🔹 ATTACH ROLE POLICY DETAILS\n"
        message += "   👤 Affected Role: " + role_name + "\n"
        message += "   📝 Policy ARN: " + policy_arn + "\n"
    elif event_name == "DetachRolePolicy":
        req_params = event.get("requestParameters", {})
        role_name = req_params.get("roleName", "N/A")
        policy_arn = req_params.get("policyArn", "N/A")
        message += "🔹 DETACH ROLE POLICY DETAILS\n"
        message += "   👤 Affected Role: " + role_name + "\n"
        message += "   📝 Policy ARN: " + policy_arn + "\n"
    elif event_name == "PutRolePolicy":
        req_params = event.get("requestParameters", {})
        role_name = req_params.get("roleName", "N/A")
        policy_name = req_params.get("policyName", "N/A")
        policy_document = req_params.get("policyDocument", "N/A")
        truncated_policy = (
            policy_document
            if len(policy_document) <= 200
            else policy_document[:200] + "... (truncated)"
        )
        message += "🔹 PUT ROLE POLICY DETAILS\n"
        message += "   👤 Affected Role: " + role_name + "\n"
        message += "   📝 Policy Name: " + policy_name + "\n"
        message += "   📄 Policy Document: " + truncated_policy + "\n"
    elif event_name == "DeleteRolePolicy":
        req_params = event.get("requestParameters", {})
        role_name = req_params.get("roleName", "N/A")
        policy_name = req_params.get("policyName", "N/A")
        message += "🔹 DELETE ROLE POLICY DETAILS\n"
        message += "   👤 Affected Role: " + role_name + "\n"
        message += "   📝 Policy Name: " + policy_name + "\n"
    elif event_name == "UpdateAssumeRolePolicy":
        req_params = event.get("requestParameters", {})
        role_name = req_params.get("roleName", "N/A")
        policy_document = req_params.get("policyDocument", "N/A")
        truncated_policy = (
            policy_document
            if len(policy_document) <= 200
            else policy_document[:200] + "... (truncated)"
        )
        message += "🔹 UPDATE ASSUME ROLE POLICY DETAILS\n"
        message += "   👤 Affected Role: " + role_name + "\n"
        message += "   📄 Policy Document: " + truncated_policy + "\n"
    elif event_name == "DeleteRole":
        req_params = event.get("requestParameters", {})
        role_name = req_params.get("roleName", "N/A")
        message += "🔹 DELETE ROLE DETAILS\n"
        message += "   👤 Role Name: " + role_name + "\n"
    elif event_name == "AttachGroupPolicy":
        req_params = event.get("requestParameters", {})
        group_name = req_params.get("groupName", "N/A")
        policy_arn = req_params.get("policyArn", "N/A")
        message += "🔹 ATTACH GROUP POLICY DETAILS\n"
        message += "   👥 Group Name: " + group_name + "\n"
        message += "   📝 Policy ARN: " + policy_arn + "\n"
    elif event_name == "CreateGroup":
        group_info = event.get("responseElements", {}).get("group", {})
        group_name = group_info.get("groupName", "N/A")
        group_id = group_info.get("groupId", "N/A")
        group_arn = group_info.get("arn", "N/A")
        create_date = group_info.get("createDate", "N/A")
        message += "🔹 CREATED GROUP DETAILS\n"
        message += "   👥 Group Name: " + group_name + "\n"
        message += "   🆔 Group ID: " + group_id + "\n"
        message += "   🔗 Group ARN: " + group_arn + "\n"
        message += "   📅 Creation Date: " + create_date + "\n"
    elif event_name == "DeleteGroup":
        req_params = event.get("requestParameters", {})
        group_name = req_params.get("groupName", "N/A")
        message += "🔹 DELETE GROUP DETAILS\n"
        message += "   👥 Group Name: " + group_name + "\n"

    
    message += "\n⚠️ Recommended Action:\n"
    message += "- If this action was not expected, investigate immediately.\n"
    message += "- Verify IAM policies and user access.\n"
    message += "- Enforce MFA for all users.\n"
    
    return message

def lambda_handler(event, context):
    try:        
        # Extract event details from CloudWatch EventBridge; fallback to full event for debugging
        event_detail = event.get("detail", event)
        
        # Format the alert message
        message = format_iam_alert(event_detail)
        
        # Publish the formatted message to SNS
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject="IAM Alert: " + event_detail.get("eventName", "Unknown Event")
        )
        
        print("Alert sent successfully!")
        return {"statusCode": 200, "body": "Alert sent"}
    except Exception as e:
        print(f"Error processing event: {str(e)}")
        return {"statusCode": 500, "body": "Error processing event"}
