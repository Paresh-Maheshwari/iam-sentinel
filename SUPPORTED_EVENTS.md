# AWS IAM Security Alert System

This repository contains a comprehensive list of AWS IAM events that are monitored for security purposes. The events are categorized based on their types and associated severity levels to help you quickly identify and respond to potential security issues.

## Table of Contents

- [AWS IAM Security Alert System](#aws-iam-security-alert-system)
  - [Table of Contents](#table-of-contents)
  - [Supported IAM Events 🔍](#supported-iam-events-)
    - [User Events 👤](#user-events-)
    - [Role Events 🎭](#role-events-)
    - [Group Events 👥](#group-events-)
  - [Severity Legend](#severity-legend)
  - [Notes](#notes)


## Supported IAM Events 🔍

### User Events 👤

| Event Name           | Type   | Description                                                                 | Severity  |
|----------------------|--------|-----------------------------------------------------------------------------|-----------|
| `CreateUser`         | User   | Creation of new IAM user. Monitor for unauthorized account creation.        | High      |
| `DeleteUser`         | User   | IAM user deletion. Could indicate account compromise or sabotage.           | Critical  |
| `CreateAccessKey`    | User   | New programmatic access key created. Risk of credential exposure.            | High      |
| `DeleteAccessKey`    | User   | Access key deleted. Could disrupt services or hide malicious activity.       | Medium    |
| `CreateLoginProfile` | User   | Console access enabled for user. Verify password setup legitimacy.           | High      |
| `UpdateLoginProfile` | User   | Console password changed. Potential password reset attack.                   | High      |
| `DeleteLoginProfile` | User   | Console access removed. May lock out legitimate users.                       | High      |
| `PutUserPolicy`      | User   | Inline policy added/modified for user. Check for excessive permissions.      | High      |
| `DeleteUserPolicy`   | User   | Inline policy removed from user. Verify intentional permission change.       | Medium    |
| `AttachUserPolicy`   | User   | Managed policy attached to user. Potential privilege escalation.             | High      |
| `DetachUserPolicy`   | User   | Managed policy removed from user. Verify intentional change.                 | Medium    |
| `AddUserToGroup`     | User   | User added to group. Could grant indirect permissions.                       | Medium    |
| `RemoveUserFromGroup`| User   | User removed from group. Verify intentional membership change.               | Medium    |
| `DeactivateMFADevice`| User   | MFA disabled for user. Critical security reduction!                          | Critical  |

### Role Events 🎭

| Event Name                 | Type   | Description                                                                 | Severity  |
|---------------------------|--------|-----------------------------------------------------------------------------|-----------|
| `CreateRole`              | Role   | New IAM role created. Verify permissions and trust policy.                  | High      |
| `DeleteRole`              | Role   | IAM role deleted. May disrupt services or erase evidence.                   | Critical  |
| `AttachRolePolicy`        | Role   | Policy attached to role. Verify for privilege escalation.                   | High      |
| `DetachRolePolicy`        | Role   | Policy detached from role. Verify intentional change.                       | Medium    |
| `PutRolePolicy`           | Role   | Inline policy added/modified for role. Check permissions.                   | High      |
| `DeleteRolePolicy`        | Role   | Inline policy removed from role. Verify intentional change.                 | Medium    |
| `UpdateAssumeRolePolicy`  | Role   | Role trust policy modified. High risk of cross-account abuse!               | Critical  |

### Group Events 👥

| Event Name           | Type   | Description                                                                 | Severity  |
|----------------------|--------|-----------------------------------------------------------------------------|-----------|
| `CreateGroup`        | Group  | New IAM group created. Verify group policy intentions.                      | Medium    |
| `DeleteGroup`        | Group  | IAM group deleted. May impact access controls.                              | Medium    |
| `AttachGroupPolicy`  | Group  | Policy attached to group. Impacts all group members.                        | High      |


## Severity Legend

- 🔴 **Critical**: Immediate security impact requiring urgent action
- 🟠 **High**: Potential security risk needing prompt investigation
- 🟡 **Medium**: Important change requiring verification
- 🔵 **Low**: Routine operation (not shown in monitored events)

## Notes

> **Note**: This list covers core monitored events. New event types are added continuously based on AWS security best practices.
