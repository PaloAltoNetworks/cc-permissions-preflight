#!/bin/bash
#
# =================================================================================
# CSP Onboarding Permissions Preflight Check Script
# =================================================================================
#
# Description:
# This script is designed to be run within a cloud service provider's (CSP)
# native cloud shell (AWS CloudShell Azure Cloud Shell Google Cloud Shell).
# It checks if the currently authenticated user possesses the superset of
# permissions required to successfully onboard a CSP environment into Cortex Cloud.
#
# The script validates permissions for:
#   - AWS (Organizations & Accounts)
#   - Azure (Tenant & Subscription)
#   - GCP (Organizations & Projects)
#
# It provides clear output indicating which required permissions are present
# and which are missing allowing the user to take corrective action before
# attempting the onboarding process.
#
# Usage:
#   ./preflight_check.sh <target>
#
#   <target> can be one of:
#     - aws-org
#     - aws-account
#     - azure-tenant
#     - azure-sub
#     - gcp-org
#     - gcp-project
#
# Pre-requisites:
#   - Must be run in the respective CSP's cloud shell.
#   - The user must be authenticated to the CLI (aws az gcloud).
#   - For GCP Org checks the user must provide the Organization ID.
#
# =================================================================================

# Set colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#Utils
# Function to print a formatted header
print_header() {
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${NC}  $1 ${NC}"
    echo -e "${BLUE}=================================================================${NC}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") -p <provider> [-h]
  -p   provider: aws-account | aws-org | azure-sub | azure-mg | azure-tenant | gcp-project | gcp-org   (required)
  -h   help
EOF
}
# Case-insensitive glob match: _ci_match <pattern> <value>
_ci_match() {
  local pat="${1,,}" str="${2,,}"
  [[ "$str" == $pat ]]   # pat unquoted on purpose to allow globs like */register/action
}

# Permission Sets for AWS Accounts
PERMISSIONS_AWS_ACCOUNT_BASE=(
    "cloudformation:CreateUploadBucket"
    "cloudformation:CreateStack"
    "cloudformation:GetTemplateSummary"
    "cloudformation:ListStacks"
    "cloudformation:DescribeStacks"
    "cloudformation:DescribeStackEvents"
    "s3:CreateBucket"
    "s3:PutObject"
    "s3:GetObject"
    "iam:CreatePolicy"
    "iam:GetRole"
    "iam:CreateRole"
    "iam:TagRole"
    "iam:AttachRolePolicy"
    "iam:DetachRolePolicy"
    "iam:PassRole"
    "lambda:CreateFunction"
    "lambda:DeleteFunction"
    "lambda:TagResource"
    "lambda:GetFunction"
    "lambda:InvokeFunction"
)
PERMISSIONS_AWS_ACCOUNT_AUDIT_LOGS=(
    "SNS:GetTopicAttributes"
    "sqs:createqueue"
    "SNS:CreateTopic"
    "SNS:TagResource"
    "sqs:tagqueue"
    "kms:TagResource"
    "kms:CreateKey"
    "kms:PutKeyPolicy"
    "SNS:SetTopicAttributes"
    "s3:PutBucketTagging"
    "s3:PutEncryptionConfiguration"
    "s3:PutLifecycleConfiguration"
    "sqs:setqueueattributes"
    "SNS:Subscribe"
    "iam:PutRolePolicy"
    "s3:PutBucketPolicy"
    "cloudtrail:CreateTrail"
    "cloudtrail:AddTags"
    "cloudtrail:StartLogging"
    "cloudtrail:PutEventSelectors"
)
PERMISSIONS_AWS_ACCOUNT_FEATURES=(
    "iam:PutRolePolicy"
)
PERMISSIONS_AWS_ORG_BASE=(
    "cloudformation:CreateUploadBucket"
    "cloudformation:CreateStack"
    "cloudformation:GetTemplateSummary"
    "cloudformation:ListStacks"
    "cloudformation:DescribeStacks"
    "cloudformation:DescribeStackEvents"
    "s3:CreateBucket"
    "s3:PutObject"
    "s3:GetObject"
    "iam:CreatePolicy"
    "iam:GetRole"
    "iam:CreateRole"
    "iam:TagRole"
    "iam:AttachRolePolicy"
    "iam:DetachRolePolicy"
    "iam:PassRole"
    "lambda:CreateFunction"
    "lambda:DeleteFunction"
    "lambda:TagResource"
    "lambda:GetFunction"
    "lambda:InvokeFunction"
    "cloudformation:CreateStackSet"
    "cloudformation:CreateStackInstances"
    "cloudformation:DescribeStackSetOperation"
)
PERMISSIONS_AWS_ORG_AUDIT_LOGS=(
    "SNS:GetTopicAttributes"
    "sqs:createqueue"
    "SNS:CreateTopic"
    "SNS:TagResource"
    "sqs:tagqueue"
    "kms:TagResource"
    "kms:CreateKey"
    "kms:PutKeyPolicy"
    "SNS:SetTopicAttributes"
    "s3:PutBucketTagging"
    "s3:PutEncryptionConfiguration"
    "s3:PutLifecycleConfiguration"
    "sqs:setqueueattributes"
    "SNS:Subscribe"
    "iam:PutRolePolicy"
    "s3:PutBucketPolicy"
    "cloudtrail:CreateTrail"
    "cloudtrail:AddTags"
    "cloudtrail:StartLogging"
    "cloudtrail:PutEventSelectors"
    "sqs:getqueueattributes"
    "cloudformation:CreateStackSet"
    "cloudformation:CreateStackInstances"
    "cloudformation:DescribeStackSetOperation"
    "sqs:getqueueattributes"
    "organizations:ListAWSServiceAccessForOrganization"
    "organizations:DescribeOrganization"
    "organizations:DescribeOrganizationalUnit"
)
PERMISSIONS_AWS_ORG_FEATURES=(
    "iam:PutRolePolicy"
)
PERMISSIONS_AZURE_SUBSCRIPTION_BASE=(
    "Microsoft.Resources/subscriptions/read"
    "Microsoft.Resources/subscriptions/resourcegroups/read"
    "Microsoft.Resources/deployments/validate/action"
    "Microsoft.Resources/subscriptions/resourcegroups/write"
    "Microsoft.Authorization/roleDefinitions/write"
    "Microsoft.Authorization/roleAssignments/write"
    "Microsoft.Resources/subscriptions/resourceGroups/delete"
    "Microsoft.Authorization/roleDefinitions/delete"
    "Microsoft.Authorization/roleAssignments/delete"
    "Microsoft.Resources/deployments/write"
    "Microsoft.Resources/deploymentScripts/write"
    "Microsoft.Resources/deployments/read"
    "Microsoft.Resources/deployments/delete"
    "Microsoft.Resources/deployments/cancel/action"
    "Microsoft.Resources/deploymentScripts/read"
    "Microsoft.Resources/deploymentScripts/delete"
    "Microsoft.Resources/deployments/operationStatuses/read"
    "Microsoft.ContainerInstance/containerGroups/read"
    "Microsoft.Resources/deployments/operationStatuses/read"
    "Microsoft.Storage/storageAccounts/read"
    "Microsoft.Storage/storageAccounts/write"
    "Microsoft.ContainerInstance/containerGroups/write"
)
PERMISSIONS_AZURE_SUBSCRIPTION_AUDIT_LOGS=(
    "Microsoft.EventHub/namespaces/write"
    "Microsoft.EventHub/namespaces/eventhubs/write"
    "Microsoft.EventHub/namespaces/authorizationRules/write"
    "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/write"
    "Microsoft.EventHub/namespaces/eventhubs/consumergroups/write"
    "Microsoft.Storage/storageAccounts/blobServices/write"
    "Microsoft.Insights/diagnosticSettings/write"
    "Microsoft.EventHub/namespaces/read"
    "Microsoft.Storage/storageAccounts/read"
    "Microsoft.Storage/storageAccounts/write"
    "Microsoft.Storage/storageAccounts/fileServices/read"
    "Microsoft.EventHub/namespaces/authorizationRules/read"
    "Microsoft.EventHub/namespaces/eventhubs/read"
    "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/read"
    "Microsoft.EventHub/namespaces/eventhubs/consumerGroups/read"
    "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action"
)
PERMISSIONS_AZURE_MG_BASE=(
    "Microsoft.Resources/subscriptions/read"
    "Microsoft.Resources/subscriptions/resourcegroups/read"
    "Microsoft.Resources/deployments/validate/action"
    "Microsoft.Resources/subscriptions/resourcegroups/write"
    "Microsoft.Authorization/roleDefinitions/write"
    "Microsoft.Authorization/roleAssignments/write"
    "Microsoft.Resources/subscriptions/resourceGroups/delete"
    "Microsoft.Authorization/roleDefinitions/delete"
    "Microsoft.Authorization/roleAssignments/delete"
    "Microsoft.Resources/deployments/write"
    "Microsoft.Resources/deploymentScripts/write"
    "Microsoft.Resources/deployments/read"
    "Microsoft.Resources/deployments/delete"
    "Microsoft.Resources/deployments/cancel/action"
    "Microsoft.Resources/deploymentScripts/read"
    "Microsoft.Resources/deploymentScripts/delete"
    "Microsoft.Resources/deployments/operationStatuses/read"
    "Microsoft.ContainerInstance/containerGroups/read"
    "Microsoft.Storage/storageAccounts/read"
    "Microsoft.Storage/storageAccounts/write"
    "Microsoft.ContainerInstance/containerGroups/write"
    "Microsoft.ManagedIdentity/userAssignedIdentities/write"
    "Microsoft.ManagedIdentity/userAssignedIdentities/read"
    "Microsoft.Authorization/roleDefinitions/read"
    "Microsoft.Authorization/roleAssignments/read"
    "Microsoft.Management/managementGroups/read"
    "Microsoft.Authorization/policyAssignments/read"
    "Microsoft.Authorization/policyAssignments/write"
    "Microsoft.Authorization/policyDefinitions/read"
    "Microsoft.Authorization/policySetDefinitions/read"
    "Microsoft.PolicyInsights/policyStates/summarize/action"
    "Microsoft.PolicyInsights/policyStates/queryResults/action"
    "Microsoft.PolicyInsights/remediations/read"
    "Microsoft.PolicyInsights/remediations/write"
)
PERMISSIONS_AZURE_MG_AUDIT_LOGS=(
    "Microsoft.Resources/subscriptions/read"
    "Microsoft.Resources/subscriptions/resourcegroups/read"
    "Microsoft.Resources/deployments/validate/action"
    "Microsoft.Resources/subscriptions/resourcegroups/write"
    "Microsoft.Authorization/roleDefinitions/write"
    "Microsoft.Authorization/roleAssignments/write"
    "Microsoft.Resources/subscriptions/resourceGroups/delete"
    "Microsoft.Authorization/roleDefinitions/delete"
    "Microsoft.Authorization/roleAssignments/delete"
    "Microsoft.Resources/deployments/write"
    "Microsoft.Resources/deploymentScripts/write"
    "Microsoft.Resources/deployments/read"
    "Microsoft.Resources/deployments/delete"
    "Microsoft.Resources/deployments/cancel/action"
    "Microsoft.Resources/deploymentScripts/read"
    "Microsoft.Resources/deploymentScripts/delete"
    "Microsoft.Resources/deployments/operationStatuses/read"
    "Microsoft.ContainerInstance/containerGroups/read"
    "Microsoft.Storage/storageAccounts/read"
    "Microsoft.Storage/storageAccounts/write"
    "Microsoft.ContainerInstance/containerGroups/write"
    "Microsoft.ManagedIdentity/userAssignedIdentities/write"
    "Microsoft.ManagedIdentity/userAssignedIdentities/read"
    "Microsoft.Authorization/roleDefinitions/read"
    "Microsoft.Authorization/roleAssignments/read"
    "Microsoft.Management/managementGroups/read"
    "Microsoft.Authorization/policyAssignments/read"
    "Microsoft.Authorization/policyAssignments/write"
    "Microsoft.Authorization/policyDefinitions/read"
    "Microsoft.Authorization/policySetDefinitions/read"
    "Microsoft.PolicyInsights/policyStates/summarize/action"
    "Microsoft.PolicyInsights/policyStates/queryResults/action"
    "Microsoft.PolicyInsights/remediations/read"
    "Microsoft.PolicyInsights/remediations/write"
    "Microsoft.EventHub/namespaces/write"
    "Microsoft.EventHub/namespaces/eventhubs/write"
    "Microsoft.EventHub/namespaces/authorizationRules/write"
    "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/write"
    "Microsoft.EventHub/namespaces/eventhubs/consumergroups/write"
    "Microsoft.Storage/storageAccounts/blobServices/write"
    "Microsoft.Insights/diagnosticSettings/write"
    "Microsoft.EventHub/namespaces/read"
    "Microsoft.Storage/storageAccounts/read"
    "Microsoft.Storage/storageAccounts/write"
    "Microsoft.Storage/storageAccounts/fileServices/read"
    "Microsoft.EventHub/namespaces/authorizationRules/read"
    "Microsoft.EventHub/namespaces/eventhubs/read"
    "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/read"
    "Microsoft.EventHub/namespaces/eventhubs/consumerGroups/read"
    "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action"
)
PERMISSIONS_GCP_PROJECT_BASE=(
    "iam.roles.create"
    "iam.roles.get"
    "iam.serviceAccounts.create"
    "iam.serviceAccounts.get"
    "iam.serviceAccounts.getIamPolicy"
    "iam.serviceAccounts.setIamPolicy"
    "resourcemanager.projects.get"
    "resourcemanager.projects.getIamPolicy"
    "resourcemanager.projects.setIamPolicy"
)
PERMISSIONS_GCP_PROJECT_AUDIT_LOGS=(
    "logging.sinks.create"
    "logging.sinks.get"
    "pubsub.subscriptions.create"
    "pubsub.subscriptions.get"
    "pubsub.subscriptions.getIamPolicy"
    "pubsub.subscriptions.setIamPolicy"
    "pubsub.topics.attachSubscription"
    "pubsub.topics.create"
    "pubsub.topics.get"
    "pubsub.topics.getIamPolicy"
    "pubsub.topics.setIamPolicy"
    "serviceusage.services.enable"
)
PERMISSIONS_GCP_ORG_BASE=(
    "iam.roles.create"
    "iam.roles.delete"
    "iam.roles.get"
    "iam.roles.undelete"
    "iam.roles.update"
    "iam.serviceAccounts.create"
    "iam.serviceAccounts.delete"
    "iam.serviceAccounts.get"
    "iam.serviceAccounts.getIamPolicy"
    "iam.serviceAccounts.setIamPolicy"
    "resourcemanager.organizations.getIamPolicy"
    "resourcemanager.organizations.setIamPolicy"
    "resourcemanager.projects.get"
    "resourcemanager.projects.getIamPolicy"
    "resourcemanager.projects.setIamPolicy"
)
PERMISSIONS_GCP_ORG_AUDIT_LOGS=(
    "iam.roles.create"
    "iam.roles.delete"
    "iam.roles.get"
    "iam.roles.undelete"
    "iam.roles.update"
    "iam.serviceAccounts.create"
    "iam.serviceAccounts.delete"
    "iam.serviceAccounts.get"
    "iam.serviceAccounts.getIamPolicy"
    "iam.serviceAccounts.setIamPolicy"
    "resourcemanager.organizations.getIamPolicy"
    "resourcemanager.organizations.setIamPolicy"
    "resourcemanager.projects.get"
    "resourcemanager.projects.getIamPolicy"
    "resourcemanager.projects.setIamPolicy"
    "logging.sinks.create"
    "logging.sinks.delete"
    "logging.sinks.get"
    "pubsub.subscriptions.create"
    "pubsub.subscriptions.delete"
    "pubsub.subscriptions.get"
    "pubsub.subscriptions.getIamPolicy"
    "pubsub.subscriptions.setIamPolicy"
    "pubsub.topics.attachSubscription"
    "pubsub.topics.create"
    "pubsub.topics.delete"
    "pubsub.topics.get"
    "pubsub.topics.getIamPolicy"
    "pubsub.topics.setIamPolicy"
    "serviceusage.services.enable"
)

# Functions
aws_account_check() {
    echo
    print_header "Starting AWS Single Account Preflight Permissions Check"
    echo
    
    set -e

    ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
    IDENTITY_ARN=$(aws sts get-caller-identity --query "Arn" --output text)

    echo "Current identity ARN: $IDENTITY_ARN"

    # Detect principal ARN
    if [[ "$IDENTITY_ARN" == *":user/"* ]]; then
        ENTITY_ARN="$IDENTITY_ARN"
    elif [[ "$IDENTITY_ARN" == *":assumed-role/"* ]]; then
        ROLE_NAME=$(echo "$IDENTITY_ARN" | awk -F'/' '{print $2}')
        ENTITY_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
    elif [[ "$IDENTITY_ARN" == *":root" ]]; then
        echo "Detected CloudShell root ARN — All permissions are satisfied"
        exit 0
    else
        echo "Unsupported identity type: $IDENTITY_ARN"
        exit 1
    fi

    echo "Simulating permissions for: $ENTITY_ARN"
    echo

    DENIED_ACTIONS=()
    aws_single_actions=("${PERMISSIONS_AWS_ACCOUNT_BASE[@]}")

    local audts=0
    local feats=0

    echo "Are you enabling - Audit Log Collection (CloudTrail)?"
    read -p "Enter your choice of yes or no (y or n): " audit_logs
    case $audit_logs in
        y|Y)
            aws_single_actions+=("${PERMISSIONS_AWS_ACCOUNT_AUDIT_LOGS[@]}")
            audts=1
            ;;
    esac

    echo 
    echo "Are you enabling at least one of the following features?"
    echo " - Data security posture management (DSPM)"
    echo " - Registry scanning"
    echo " - Serverless function scanning"

    read -p "Enter your choice of yes or no (y or n): " aws_features
    case $aws_features in
        y|Y)
            aws_single_actions+=("${PERMISSIONS_AWS_ACCOUNT_FEATURES[@]}")
            feats=1
            ;;
    esac

    echo

    # Check each action
    print_header "Checking Required Permissions"
    for ACTION in "${aws_single_actions[@]}"; do
        RESULT=$(aws iam simulate-principal-policy \
            --policy-source-arn "$ENTITY_ARN" \
            --action-names "$ACTION" \
            --query "EvaluationResults[0].EvalDecision" \
            --output text 2>/dev/null || echo "ERROR")

        if [[ "$RESULT" =~ ^[Aa]llowed$ ]]; then
            echo -e "$ACTION: ${GREEN}Allowed${NC}"
        elif [[ "$RESULT" =~ ^[Dd]enied$ ]]; then
            echo -e "$ACTION: ${RED}Denied${NC}"
            DENIED_ACTIONS+=("$ACTION")
        else
            echo "$ACTION Failed verifying this permission."
            DENIED_ACTIONS+=("$ACTION")
        fi
    done
    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options: " 
    (( audts == 0 )) && echo " - Audit Log Collection not enabled" || echo " - Audit Log Collection enabled"
    (( feats == 0 )) && echo " - DSPM, Registry Scanning and Serverless function scanning disabled." || echo " - DSPM, Registry Scanning and/or Serverless function Scanning enabled."
    echo
    echo "This identity was checked:"
    echo " - Identity ARN: $IDENTITY_ARN"
    echo " - ACCOUNT ID: $ACCOUNT_ID"
    echo
    if [ ${#DENIED_ACTIONS[@]} -eq 0 ]; then
        echo -e "${GREEN}Verdict: You have the required permissions.${NC}"
    else
        echo -e "${RED}Verdict: You are missing these permissions:${NC}"
        for PERM in "${DENIED_ACTIONS[@]}"; do
            echo " - $PERM"
        done
        echo 
        echo "Please contact an administrator to enable those permissions."
        exit 1
    fi
}
aws_organization_check() {
    echo
    print_header "Starting AWS Organization Preflight Permissions Check"
    echo

    set -e

    local ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
    local IDENTITY_ARN=$(aws sts get-caller-identity --query "Arn" --output text)
    echo "Current identity ARN: $IDENTITY_ARN"
    echo

    echo "Checking AWS Organization Master Account"

    local ORG_ID=$(aws organizations describe-organization --query 'Organization.MasterAccountId' --output text)

    if [[ "$ACCOUNT_ID" == "$ORG_ID" ]]; then
        echo
        echo "Master Account session detected"
    elif [[ "$ORG_ID" == *"AccessDeniedException"* ]]; then
        echo
        echo "Unable to detect master account session due to lack of permissions."
        echo "You won't be able to onboard AWS Organization from a Non-Master Organization Account"
        echo "Running permissions check anyway..."
    else
        echo
        echo "AWS Organization Master Account not detected."
        echo
        echo "${RED}Failed Preflight Permissions Check${NC}"
        echo "Please login in the Master Account and make sure you have permissions over the Organization"
        echo " - organizations:DescribeOrganization"
        echo " - organizations:DescribeOrganizationalUnit"
        echo
        exit 1
    fi 

    # Detect principal ARN
    if [[ "$IDENTITY_ARN" == *":user/"* ]]; then
        ENTITY_ARN="$IDENTITY_ARN"
    elif [[ "$IDENTITY_ARN" == *":assumed-role/"* ]]; then
        ROLE_NAME=$(echo "$IDENTITY_ARN" | awk -F'/' '{print $2}')
        ENTITY_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
    elif [[ "$IDENTITY_ARN" == *":root" ]]; then
        echo "Detected CloudShell root ARN — All permissions are satisfied"
        exit 1
    else
        echo "Unsupported identity type: $IDENTITY_ARN"
        exit 1
    fi

    echo "Simulating permissions for: $ENTITY_ARN"
    echo

    DENIED_ACTIONS=()

    local audts=0
    local feats=0

    echo "Are you enabling - Audit Log Collection (CloudTrail)?"
    read -p "Enter your choice of yes or no (y or n): " audit_logs
    case $audit_logs in
        y)
            aws_org_actions=("${PERMISSIONS_AWS_ORG_BASE[@]}" "${PERMISSIONS_AWS_ORG_AUDIT_LOGS[@]}")
            audts=1
            ;;
        n)
            aws_org_actions=("${PERMISSIONS_AWS_ORG_BASE[@]}")
            ;;
    esac

    echo 
    echo "Are you enabling at least one of the following features?"
    echo " - Data security posture management (DSPM)"
    echo " - Registry scanning"
    echo " - Serverless function scanning"

    read -p "Enter your choice of yes or no (y or n): " aws_features

    case $aws_features in
        y)
            aws_org_actions=("${aws_org_actions[@]}" "${PERMISSIONS_AWS_ORG_FEATURES[@]}")
            feats=1
            ;;
        n)
            ;;
    esac

    # Check each action
    echo
    print_header "Checking Required Permissions"
    for ACTION in "${aws_org_actions[@]}"; do
        RESULT=$(aws iam simulate-principal-policy \
            --policy-source-arn "$ENTITY_ARN" \
            --action-names "$ACTION" \
            --query "EvaluationResults[0].EvalDecision" \
            --output text 2>/dev/null || echo "ERROR")

        if [[ "$RESULT" =~ ^[Aa]llowed$ ]]; then
            echo -e "$ACTION: ${GREEN}Allowed${NC}"
        elif [[ "$RESULT" =~ ^[Dd]enied$ ]]; then
            echo "$ACTION: Denied"
            DENIED_ACTIONS+=("$ACTION")
        else
            echo "$ACTION Failed verifying this permission."
            DENIED_ACTIONS+=("$ACTION")
        fi
    done
    
    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options: " 
    (( audts == 0 )) && echo " - Audit Log Collection not enabled" || echo " - Audit Log Collection enabled"
    (( feats == 0 )) && echo " - DSPM, Registry Scanning and Serverless function scanning disabled." || echo " - DSPM, Registry Scanning and/or Serverless function Scanning enabled."
    echo
    echo "This identity was checked:"
    echo " - Identity ARN: $IDENTITY_ARN"
    echo " - ACCOUNT ID: $ACCOUNT_ID"
    echo " - Organization Master ACCOUNT ID: $ORG_ID"
    echo
    echo "Make sure these services are active in your AWS Organization:"
    echo " - AWS Account Management"
    echo " - AWS CloudFormation StackSets"
    echo " - CloudTrail"
    echo
    echo "Make sure you have a service-linked role for CloudTrail."

    echo
    if [ ${#DENIED_ACTIONS[@]} -eq 0 ]; then
        echo -e "${GREEN}Verdict: You have the required permissions.${NC}"
    else
        echo -e "${RED}Verdict: You are missing these permissions:${NC}"
        for PERM in "${DENIED_ACTIONS[@]}"; do
            echo " - $PERM"
        done
        echo 
        echo "Please contact an administrator to enable those permissions."
    fi
}
azure_subscription_check() {
    echo
    print_header "Starting Azure Subscription Preflight Permissions Check"
    echo
    echo "Note: Some delete permissions are included for rollback. They're not required for Onboarding."
    echo
    # deps
    command -v az >/dev/null || { echo "az CLI not found" >&2; return 2; }
    command -v jq >/dev/null || { echo "jq not found (Cloud Shell usually has it)" >&2; return 2; }

    # scope
    local SUBSCRIPTION_ID SCOPE ASSIGNEE
    SUBSCRIPTION_ID="$(az account show --query id -o tsv 2>/dev/null)" || { echo "Cannot get subscription id" >&2; return 2; }
    [[ -n "$SUBSCRIPTION_ID" ]] || { echo "Empty subscription id" >&2; return 2; }
    SCOPE="/subscriptions/${SUBSCRIPTION_ID}"

    # current principal (objectId if possible, else UPN)
    ASSIGNEE="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
    [[ -z "$ASSIGNEE" ]] && ASSIGNEE="$(az account show --query user.name -o tsv 2>/dev/null || true)"
    [[ -n "$ASSIGNEE" ]] || { echo "Cannot resolve current principal (objectId or UPN)" >&2; return 2; }

    # role assignments & definitions
    local assignments role_ids roles_json
    # --scope "$SCOPE" eliminated since the user has to have this role at the rg level that will be created in the subscription.
    assignments="$(
        az role assignment list \
            --assignee "$ASSIGNEE" \
            --include-inherited \
            --scope "$SCOPE" \
            --include-groups \
            -o json
    )" || { echo "Failed to list role assignments" >&2; return 2; }
    role_ids="$(jq -r '.[].roleDefinitionId' <<<"$assignments" | sort -u)"
    roles_json="$(az role definition list -o json)" || { echo "Failed to list role definitions" >&2; return 2; }

    # effective sets
    local EFFECTIVE_ACTIONS=() EFFECTIVE_NOTACTIONS=() EFFECTIVE_DATAACTIONS=() EFFECTIVE_NOTDATAACTIONS=()
    while IFS= read -r rid; do
        [[ -z "$rid" ]] && continue
        local role
        role="$(jq -c --arg rid "$rid" '.[] | select(.id==$rid or .name==$rid)' <<<"$roles_json")"
        [[ -z "$role" ]] && continue
        mapfile -t _a   < <(jq -r '.permissions[]?.actions[]?'         <<<"$role")
        mapfile -t _na  < <(jq -r '.permissions[]?.notActions[]?'      <<<"$role")
        mapfile -t _da  < <(jq -r '.permissions[]?.dataActions[]?'     <<<"$role")
        mapfile -t _nda < <(jq -r '.permissions[]?.notDataActions[]?'  <<<"$role")
        EFFECTIVE_ACTIONS+=("${_a[@]}");   EFFECTIVE_NOTACTIONS+=("${_na[@]}")
        EFFECTIVE_DATAACTIONS+=("${_da[@]}"); EFFECTIVE_NOTDATAACTIONS+=("${_nda[@]}")
    done <<<"$role_ids"

    # de-dup
    mapfile -t EFFECTIVE_ACTIONS        < <(printf "%s\n" "${EFFECTIVE_ACTIONS[@]}"        | awk 'NF' | sort -u)
    mapfile -t EFFECTIVE_NOTACTIONS     < <(printf "%s\n" "${EFFECTIVE_NOTACTIONS[@]}"     | awk 'NF' | sort -u)
    mapfile -t EFFECTIVE_DATAACTIONS    < <(printf "%s\n" "${EFFECTIVE_DATAACTIONS[@]}"    | awk 'NF' | sort -u)
    mapfile -t EFFECTIVE_NOTDATAACTIONS < <(printf "%s\n" "${EFFECTIVE_NOTDATAACTIONS[@]}" | awk 'NF' | sort -u)

    # wildcard matcher: allow patterns like Microsoft.*/*/read
    _match() { local pat="$1" str="$2"; [[ "$str" == $pat ]]; }

    echo "Are you enabling Audit Log Collection?"
    read -p "Enter your choice of yes or no (y or n): " audit_logs
    local audts=0

    local azure_single_actions=("${PERMISSIONS_AZURE_SUBSCRIPTION_BASE[@]}")
    case $audit_logs in
        y|Y)
            azure_single_actions+=("${PERMISSIONS_AZURE_SUBSCRIPTION_AUDIT_LOGS[@]}")
            audts=1
            ;;
    esac

    echo 

    # iterate required list from global azure_single_actions
    local missing=()
    for req in "${azure_single_actions[@]}"; do
        [[ -z "$req" ]] && continue
        # excluded by NotActions/NotDataActions?
        local excluded=""
        for na in "${EFFECTIVE_NOTACTIONS[@]}"; do
            [[ -n "$na" ]] && _ci_match "$na" "$req" && { excluded=1; break; }
        done
        if [[ -z "$excluded" ]]; then
            for na in "${EFFECTIVE_NOTDATAACTIONS[@]}"; do
            [[ -n "$na" ]] && _ci_match "$na" "$req" && { excluded=1; break; }
            done
        fi
        [[ -n "$excluded" ]] && { missing+=("$req (blocked by NotActions)"); continue; }
        # covered by Actions OR DataActions (whichever matches)
        local ok=""
        for allow in "${EFFECTIVE_ACTIONS[@]}"; do
            _ci_match "$allow" "$req" && { ok=1; break; }
        done
        if [[ -z "$ok" ]]; then
            for allow in "${EFFECTIVE_DATAACTIONS[@]}"; do
            _ci_match "$allow" "$req" && { ok=1; break; }
            done
        fi
        [[ -z "$ok" ]] && missing+=("$req")
        done

    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options: " 
    (( audts == 0 )) && echo " - Audit Log Collection not enabled" || echo " - Audit Log Collection enabled"
    echo
    echo "Assignee: $ASSIGNEE"
    echo "Scope:    $SCOPE"
    echo
    if (( ${#missing[@]} == 0 )); then
        echo -e "${GREEN}Actions OK${NC} all required actions are satisfied."
        printf '  -%s\n' "${azure_single_actions[@]}"
        echo
        echo "You can onboard this Azure subscription ($SUBSCRIPTION_ID) in Cortex Cloud"
        return 0
    else
        echo -e "${GREEN}You have the following required actions:"
        mapfile -t DIF < <(printf '%s\n' "${azure_single_actions[@]}" \
        | grep -Fxv -f <(printf '%s\n' "${missing[@]}"))
        printf '%s\n' "${DIF[@]}"
        echo
        echo -e "${RED}Missing permissions:"
        printf ' - %s\n' "${missing[@]}"
        return 1
    fi
}
azure_management_group_check() {
    echo
    print_header "Starting Azure Management Group Preflight Permissions Check"
    echo
    echo "Note: Some delete permissions are included for rollback. They're not required for Onboarding."
    echo
    # deps
    command -v az >/dev/null || { echo "az CLI not found" >&2; return 2; }
    command -v jq >/dev/null || { echo "jq not found (Cloud Shell usually has it)" >&2; return 2; }

    # management group scope
    local MG_ID MG_SCOPE ASSIGNEE
    MG_ID="${AZURE_MG_ID:-}"
    [[ -z "$MG_ID" ]] && read -rp "Enter Management Group ID: " MG_ID
    [[ -n "$MG_ID" ]] || { echo "Empty Management Group ID" >&2; return 2; }
    MG_SCOPE="/providers/Microsoft.Management/managementGroups/${MG_ID}"

    # current principal (objectId if possible, else UPN)
    ASSIGNEE="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
    [[ -z "$ASSIGNEE" ]] && ASSIGNEE="$(az account show --query user.name -o tsv 2>/dev/null || true)"
    [[ -n "$ASSIGNEE" ]] || { echo "Cannot resolve current principal (objectId or UPN)" >&2; return 2; }

    # role assignments (MG scope + inherited + group-based)
    local assignments role_ids roles_json
    assignments="$(
        az role assignment list \
            --assignee "$ASSIGNEE" \
            --scope "$MG_SCOPE" \
            --include-inherited \
            --include-groups \
            -o json
    )" || { echo "Failed to list role assignments at management group scope" >&2; return 2; }

    role_ids="$(jq -r '.[].roleDefinitionId' <<<"$assignments" | sort -u)"
    roles_json="$(az role definition list --scope "$MG_SCOPE" -o json)" || { echo "Failed to list role definitions" >&2; return 2; }

    # build effective allow sets
    local EFFECTIVE_ACTIONS=() EFFECTIVE_NOTACTIONS=() EFFECTIVE_DATAACTIONS=() EFFECTIVE_NOTDATAACTIONS=()
    while IFS= read -r rid; do
        rid_guid="${rid##*/}"  # extract the GUID
        role="$(jq -c --arg rid "$rid" --arg gid "$rid_guid" '
        .[] | select(
            .id == $rid
            or .name == $gid
            or (.id | endswith($gid))
        )' <<<"$roles_json")"
        [[ -z "$rid" ]] && continue
        local role
        role="$(jq -c --arg rid "$rid" '.[] | select(.id==$rid or .name==$rid)' <<<"$roles_json")"
        [[ -z "$role" ]] && continue
        mapfile -t _a   < <(jq -r '.permissions[]?.actions[]?'         <<<"$role")
        mapfile -t _na  < <(jq -r '.permissions[]?.notActions[]?'      <<<"$role")
        mapfile -t _da  < <(jq -r '.permissions[]?.dataActions[]?'     <<<"$role")
        mapfile -t _nda < <(jq -r '.permissions[]?.notDataActions[]?'  <<<"$role")
        EFFECTIVE_ACTIONS+=("${_a[@]}");       EFFECTIVE_NOTACTIONS+=("${_na[@]}")
        EFFECTIVE_DATAACTIONS+=("${_da[@]}");  EFFECTIVE_NOTDATAACTIONS+=("${_nda[@]}")
    done <<<"$role_ids"

    # de-dup
    mapfile -t EFFECTIVE_ACTIONS        < <(printf "%s\n" "${EFFECTIVE_ACTIONS[@]}"        | awk 'NF' | sort -u)
    mapfile -t EFFECTIVE_NOTACTIONS     < <(printf "%s\n" "${EFFECTIVE_NOTACTIONS[@]}"     | awk 'NF' | sort -u)
    mapfile -t EFFECTIVE_DATAACTIONS    < <(printf "%s\n" "${EFFECTIVE_DATAACTIONS[@]}"    | awk 'NF' | sort -u)
    mapfile -t EFFECTIVE_NOTDATAACTIONS < <(printf "%s\n" "${EFFECTIVE_NOTDATAACTIONS[@]}" | awk 'NF' | sort -u)

    # helpers
    _ci_match() { local pat="${1,,}" str="${2,,}"; [[ $str == $pat ]]; }  # case-insensitive glob
    _is_mg_root() {
        local s="${1,,}" mg="/providers/microsoft.management/managementgroups/${MG_ID,,}"
        [[ "$s" == "$mg" ]]
    }

    # Deny assignments at MG scope (can block even if a role allows)
    local denies
        denies="$(
            az rest --method get \
                --url "https://management.azure.com${MG_SCOPE}/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01&%24filter=atScope()" \
                -o json || true
            )"

    declare -a EFFECTIVE_DENY_ACTIONS_SCOPED=() EFFECTIVE_DENY_DATAACTIONS_SCOPED=()
    mapfile -t EFFECTIVE_DENY_ACTIONS_SCOPED < <(
        jq -r '.value[]? | select(.properties.scope!=null)
                | "\(.properties.scope)|\(.properties.permissions[]?.denyActions[]?)"' <<<"$denies"
    )
    mapfile -t EFFECTIVE_DENY_DATAACTIONS_SCOPED < <(
        jq -r '.value[]? | select(.properties.scope!=null)
                | "\(.properties.scope)|\(.properties.permissions[]?.denyDataActions[]?)"' <<<"$denies"
    )

    _blocked_at_mg() {
        local req="$1" entry scope action
        for entry in "${EFFECTIVE_DENY_ACTIONS_SCOPED[@]}"; do
            IFS='|' read -r scope action <<<"$entry"
            _is_mg_root "$scope" && _ci_match "$action" "$req" && return 0
        done
        for entry in "${EFFECTIVE_DENY_DATAACTIONS_SCOPED[@]}"; do
            IFS='|' read -r scope action <<<"$entry"
            _is_mg_root "$scope" && _ci_match "$action" "$req" && return 0
        done
        return 1
    }

    # ask which feature sets to include
    local -a azure_mg_required=("${PERMISSIONS_AZURE_MG_BASE[@]}")

    local audts=0 
    echo "Enable additional audit/diagnostics permissions for MG (if required by your template)?"
    read -rp "Answer y/n: " mg_audit
    case "$mg_audit" in
        y|Y) azure_mg_required+=("${PERMISSIONS_AZURE_MG_AUDIT_LOGS[@]}") 
        audts=1        
        ;;
    esac

    # de-dup required
    mapfile -t azure_mg_required < <(printf "%s\n" "${azure_mg_required[@]}" | awk 'NF' | sort -u)

    # evaluate
    local missing=()
    for req in "${azure_mg_required[@]}"; do
        [[ -z "$req" ]] && continue

      # blocked by Deny at MG root?
        if _blocked_at_mg "$req"; then
            missing+=("$req (blocked by Deny at MG)")
            continue
        fi

        # covered by Actions OR DataActions (case-insensitive, supports globs) (There is no data action in mapped permissions but were included in case it'll be needed)
        local ok=""
        for allow in "${EFFECTIVE_ACTIONS[@]}"; do
            _ci_match "$allow" "$req" && { ok=1; break; }
        done
        if [[ -z "$ok" ]]; then
            for allow in "${EFFECTIVE_DATAACTIONS[@]}"; do
            _ci_match "$allow" "$req" && { ok=1; break; }
            done
        fi

        [[ -z "$ok" ]] && missing+=("$req")
    done

    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options: " 
    (( audts == 0 )) && echo " - Audit Log Collection not enabled" || echo " - Audit Log Collection enabled"
    echo
    echo "Assignee: $ASSIGNEE"
    echo "Management Group Scope: $MG_SCOPE"
    echo 
    if (( ${#missing[@]} == 0 )); then
        echo -e "${GREEN}Permissions OK${NC} — all required entries for MG scope are satisfied."
        printf ' - %s\n' "${azure_mg_required[@]}"
        return 0
    else
        echo -e "${RED}Missing permissions at MG scope:${NC}"
        printf ' - %s\n' "${missing[@]}"
        return 1
    fi
}
azure_tenant_check() {
    echo
    print_header "Checking Entra ID role: Global Administrator"
    echo
    # deps
    command -v az >/dev/null || { echo -e "${RED}az CLI not found${NC}" >&2; return 2; }
    command -v jq >/dev/null || { echo -e "${RED}jq not found${NC}" >&2; return 2; }

    # scope / identity
    local TENANT_ID UPN OBJECT_ID
    TENANT_ID="${AZURE_TENANT_ID:-$(az account show --query tenantId -o tsv 2>/dev/null)}"
    [[ -n "$TENANT_ID" ]] || { echo -e "${RED}Cannot resolve tenant ID${NC}" >&2; return 2; }

    UPN="$(az account show --query user.name -o tsv 2>/dev/null || true)"
    OBJECT_ID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"

    echo "Tenant:          $TENANT_ID"
    [[ -n "$UPN"       ]] && echo "Signed-in UPN:    $UPN"
    [[ -n "$OBJECT_ID" ]] && echo "Signed-in Obj ID: $OBJECT_ID"
    echo

    # Microsoft Graph (Entra) — Global Admin template ID
    local GA_TEMPLATE_ID="62e90394-69f5-4237-9190-012177145e10"  # Company Administrator

    # 1) Find the directoryRole instance for Global Admin (must be activated in the tenant)
    local roles_json role_id
    if ! roles_json="$(
        az rest \
        --resource "https://graph.microsoft.com" \
        --method GET \
        --url "https://graph.microsoft.com/v1.0/directoryRoles?\$filter=roleTemplateId%20eq%20'$GA_TEMPLATE_ID'" \
        -o json 2>/dev/null
    )"; then
        echo -e "${RED}Failed to query Microsoft Graph (directoryRoles).${NC}" >&2
        echo "Tip: An admin may need to grant the Azure CLI app 'Read directory data' (Directory.Read.All) or 'RoleManagement.Read.Directory' in Entra ID."
        return 2
    fi

    # Handle Graph errors
    if jq -e '.error' >/dev/null 2>&1 <<<"$roles_json"; then
        echo -e "${RED}Graph error:${NC} $(jq -r '.error.message' <<<"$roles_json")" >&2
        echo "Tip: Ask a Global Admin to grant admin consent for the Azure CLI app to read directory roles."
        return 2
    fi

    role_id="$(jq -r '.value[0].id // empty' <<<"$roles_json")"
    if [[ -z "$role_id" ]]; then
        echo -e "${YELLOW}Global Administrator directory role is not activated in this tenant (unexpected).${NC}"
        echo "Result: ${RED}NOT Global Admin${NC}"
        return 1
    fi

    # 2) Check if *current user* is a member of that directoryRole via me/checkMemberObjects
    local payload check_resp
    payload="$(jq -n --arg rid "$role_id" '{ids:[$rid]}')"

    if ! check_resp="$(
        az rest \
        --resource "https://graph.microsoft.com" \
        --method POST \
        --url "https://graph.microsoft.com/v1.0/me/checkMemberObjects" \
        --headers "Content-Type=application/json" \
        --body "$payload" \
        -o json 2>/dev/null
    )"; then
        echo -e "${RED}Failed to query Microsoft Graph (me/checkMemberObjects).${NC}" >&2
        echo "Tip: This typically requires Directory.Read.All or RoleManagement.Read.Directory (delegated) consent for the Azure CLI app."
        return 2
    fi

    if jq -e '.error' >/dev/null 2>&1 <<<"$check_resp"; then
        echo -e "${RED}Graph error:${NC} $(jq -r '.error.message' <<<"$check_resp")" >&2
        return 2
    fi

    if jq -e --arg rid "$role_id" '.value[]? | select(. == $rid)' >/dev/null 2>&1 <<<"$check_resp"; then
        echo -e "Result: ${GREEN}You ARE a Global Administrator in this tenant.${NC}"
        echo -e "${NC}You can onboard the Azure Tenant to Cortex Cloud.${NC}"
        return 0
    else
        echo -e "Result: ${RED}You are NOT a Global Administrator in this tenant.${NC}"
        echo -e "${NC}You can NOT onboard the Azure Tenant to Cortex Cloud.${NC}"
        return 1
    fi
}
gcp_project_check() {
    echo
    print_header "Starting GCP Project Preflight Permissions Check"
    echo
    echo "================================================================="
    echo " NOTE: Some permissions (delete/undelete) are included for rollback"
    echo "       and cleanup purposes. They are NOT required for onboarding."
    echo "================================================================="

    # deps
    command -v gcloud >/dev/null || { echo "gcloud CLI not found" >&2; return 2; }
    command -v jq >/dev/null     || { echo "jq not found (Cloud Shell usually has it)" >&2; return 2; }
    command -v curl >/dev/null   || { echo "curl not found" >&2; return 2; }

    # context
    local PROJECT_ID ACCOUNT
    PROJECT_ID="$(gcloud config get-value project 2>/dev/null)"
    [[ -z "$PROJECT_ID" ]] && read -rp "Enter GCP Project ID: " PROJECT_ID
    [[ -n "$PROJECT_ID" ]] || { echo "Empty project id" >&2; return 2; }

    ACCOUNT="$(gcloud config get-value account 2>/dev/null)"
    [[ -n "$ACCOUNT" ]] || { echo "Cannot resolve current account (gcloud auth)" >&2; return 2; }

    echo "Project: $PROJECT_ID"
    echo "Account: $ACCOUNT"
    echo

    # compose required permissions from the predefined arrays
    local -a req_perms
    req_perms=("${PERMISSIONS_GCP_PROJECT_BASE[@]}")
    local audts=0

    echo "Enable collection of Cloud Audit Logs or related sinks (if your template needs it)?"
    read -rp "Answer y/n: " audit_logs
    case "$audit_logs" in
        y|Y) req_perms+=("${PERMISSIONS_GCP_PROJECT_AUDIT_LOGS[@]}") 
            audts=1
            ;;
    esac

    # de-dup + strip empties
    mapfile -t req_perms < <(printf '%s\n' "${req_perms[@]}" | awk 'NF' | sort -u)

    # nothing to check?
    if ((${#req_perms[@]} == 0)); then
        echo -e "${YELLOW}No GCP permissions listed to check (arrays are empty).${NC}"
        return 0
    fi

    # acquire token
    local ACCESS_TOKEN
    ACCESS_TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || { echo "Failed to get access token" >&2; return 2; }
    [[ -n "$ACCESS_TOKEN" ]] || { echo "Empty access token" >&2; return 2; }

    # helper to test up to 90-100 perms per call (API supports large lists, keep batches modest)
    local -a missing=() granted_batch=()

    _test_batch() {
        local -a batch=("$@")
        local json_perms payload resp
        json_perms="$(printf '%s\n' "${batch[@]}" | jq -R . | jq -s .)"
        payload="$(jq -n --argjson perms "$json_perms" '{permissions:$perms}')"

        resp="$(curl -sS -X POST \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT_ID}:testIamPermissions")" || return 3

      # error handling
        if jq -e '.error' >/dev/null 2>&1 <<<"$resp"; then
            echo -e "${RED}Error from testIamPermissions:${NC} $(jq -r '.error.message' <<<"$resp")" >&2
            return 3
        fi

        mapfile -t granted_batch < <(jq -r '.permissions[]?' <<<"$resp")
        # mark any not returned as missing
        local p had
        for p in "${batch[@]}"; do
            had=""
            for g in "${granted_batch[@]}"; do
            [[ "$p" == "$g" ]] && { had=1; break; }
            done
            [[ -z "$had" ]] && missing+=("$p")
        done
        return 0
    }

    # run in batches
    local i step=90
    for ((i=0; i<${#req_perms[@]}; i+=step)); do
        _test_batch "${req_perms[@]:i:step}" || { echo "Test call failed" >&2; return 2; }
    done
    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options: " 
    (( audts == 0 )) && echo " - Audit Log Collection disabled" || echo " - Audit Log Collection enabled"
    echo
    echo "Scope: $PROJECT_ID"
    echo
    if ((${#missing[@]} == 0)); then
        echo -e "${GREEN}Permissions OK${NC} — all required GCP project permissions are granted."
        printf ' - %s\n' "${req_perms[@]}"
        return 0
    else
        echo -e "${RED}Missing permissions:${NC}"
        printf ' - %s\n' "${missing[@]}"
        return 1
    fi
}
gcp_org_check() {
    echo
    print_header "Starting GCP Organization Preflight Permissions Check"
    echo
    echo "================================================================="
    echo " NOTE: Some permissions (delete/undelete) are included for rollback"
    echo "       and cleanup purposes. They are NOT required for onboarding."
    echo "================================================================="

    # deps
    command -v gcloud >/dev/null || { echo "gcloud CLI not found" >&2; return 2; }
    command -v jq >/dev/null     || { echo "jq not found (Cloud Shell usually has it)" >&2; return 2; }
    command -v curl >/dev/null   || { echo "curl not found" >&2; return 2; }

    # resolve account
    local ACCOUNT
    ACCOUNT="$(gcloud config get-value account 2>/dev/null)"
    [[ -n "$ACCOUNT" ]] || { echo "Cannot resolve current account (gcloud auth)." >&2; return 2; }

    # resolve organization id (numeric); prefer $GCP_ORG_ID if set, else auto-pick, else prompt
    local ORG_ID ORG_NUM
    ORG_ID="${GCP_ORG_ID:-}"
    if [[ -z "$ORG_ID" ]]; then
        mapfile -t _orgs < <(gcloud organizations list --format="value(ID)" 2>/dev/null || true)
        if ((${#_orgs[@]} == 1)); then
            ORG_ID="${_orgs[0]}"
        else
            echo
            echo -e "${RED}Failed fetching Organization data.${NC} You can't onboard this GCP Organization."
            echo
            exit 1
        fi
    fi
    if [[ -z "$ORG_ID" ]]; then
        read -rp "Enter GCP Organization ID (numeric, e.g. 123456789012): " ORG_ID
    fi
    [[ -n "$ORG_ID" ]] || { echo "Empty organization id" >&2; return 2; }
    ORG_NUM="${ORG_ID#organizations/}"   # normalize if user passed "organizations/1234"

    echo "Organization: organizations/${ORG_NUM}"
    echo "Account:      ${ACCOUNT}"
    echo

    # quick existence / access sanity (best-effort)
    # --- Organization Policy Check: constraints/iam.allowedPolicyMemberDomains ---
    # This org policy can restrict which identity domains may be added to IAM policies.
    # If configured, onboarding Cortex Cloud service accounts/groups outside the allowed domains
    # may fail. We surface a warning with the configured values.
    if gcloud org-policies describe constraints/iam.allowedPolicyMemberDomains \
         --organization "${ORG_NUM}" --format=json >/tmp/_iam_domain_policy.json 2>/dev/null; then

        # Parse both Org Policy v1 (listPolicy) and v2 (spec.rules[].values)
        local _allowed_json _denied_json _all_values _has_restriction
        _allowed_json="$(jq -r '
            if .spec and (.spec.rules // []) | length > 0 then
              [ .spec.rules[]? | .values.allowedValues[]? ] | unique
            elif .listPolicy then
              (.listPolicy.allowedValues // [])
            else [] end
          ' /tmp/_iam_domain_policy.json)"
        _denied_json="$(jq -r '
            if .spec and (.spec.rules // []) | length > 0 then
              [ .spec.rules[]? | .values.deniedValues[]? ] | unique
            elif .listPolicy then
              (.listPolicy.deniedValues // [])
            else [] end
          ' /tmp/_iam_domain_policy.json)"
        _all_values="$(jq -r '
            if .listPolicy and .listPolicy.allValues then .listPolicy.allValues
            else empty end
          ' /tmp/_iam_domain_policy.json)"

        # Determine if policy is effectively restricting
        _has_restriction=
        if [[ -n "$_all_values" && "$_all_values" != "ALLOW" ]]; then
            _has_restriction=1
        fi
        if jq -e 'length>0' <<<"$_allowed_json" >/dev/null 2>&1; then
            _has_restriction=1
        fi
        if jq -e 'length>0' <<<"$_denied_json" >/dev/null 2>&1; then
            _has_restriction=1
        fi

        if [[ -n "$_has_restriction" ]]; then
            echo -e "${YELLOW}Note:${NC} Org Policy ${BOLD}constraints/iam.allowedPolicyMemberDomains${NC} is configured."
            if jq -e 'length>0' <<<"$_allowed_json" >/dev/null 2>&1; then
                echo "  Allowed member domains:"
                jq -r '.[]' <<<"$_allowed_json" | sed 's/^/    - /'
            fi
            if jq -e 'length>0' <<<"$_denied_json" >/dev/null 2>&1; then
                echo "  Denied member domains:"
                jq -r '.[]' <<<"$_denied_json" | sed 's/^/    - /'
            fi
            if [[ -n "$_all_values" && "$_all_values" != "ALLOW" ]]; then
                echo "  allValues: ${_all_values}"
            fi
            echo -e "${YELLOW}Warning:${NC} This policy may block onboarding between GCP and Cortex Cloud if required identities are not within the allowed domains."
            echo "          Consider temporarily relaxing or adding the necessary domains during onboarding."
        else
            echo -e "${GREEN}Org Policy present but not restricting domains (no allowed/denied list and allValues=ALLOW).${NC}"
        fi
        rm -f /tmp/_iam_domain_policy.json
    else
        echo -e "${GREEN}No organization policy found for constraints/iam.allowedPolicyMemberDomains (not configured).${NC}"
    fi
    # --- End Organization Policy Check ---

    if ! gcloud organizations describe "organizations/${ORG_NUM}" >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning:${NC} Unable to describe organization (may lack resourcemanager.organizations.get). Continuing with permission checks..."
    fi

    # build required permissions from predefined arrays
    local -a req_perms
    req_perms=("${PERMISSIONS_GCP_ORG_BASE[@]}")

    echo "Enable additional org-level audit/diagnostics permissions (if required by your template)?"
    read -rp "Answer y/n: " audit_logs
    case "$audit_logs" in
        y|Y) req_perms+=("${PERMISSIONS_GCP_ORG_AUDIT_LOGS[@]}") ;;
    esac

    # de-dup + strip empties
    mapfile -t req_perms < <(printf '%s\n' "${req_perms[@]}" | awk 'NF' | sort -u)

    if ((${#req_perms[@]} == 0)); then
        echo -e "${YELLOW}No GCP org permissions listed to check (arrays are empty).${NC}"
        return 0
    fi

    # access token
    local ACCESS_TOKEN
    ACCESS_TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || { echo "Failed to get access token" >&2; return 2; }
    [[ -n "$ACCESS_TOKEN" ]] || { echo "Empty access token" >&2; return 2; }

    # function to call testIamPermissions in batches
    local -a missing=() granted_batch=()

    _test_org_batch() {
        local -a batch=("$@")
        local json_perms payload resp
        json_perms="$(printf '%s\n' "${batch[@]}" | jq -R . | jq -s .)"
        payload="$(jq -n --argjson perms "$json_perms" '{permissions:$perms}')"

        resp="$(curl -sS -X POST \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "https://cloudresourcemanager.googleapis.com/v1/organizations/${ORG_NUM}:testIamPermissions")" || return 3

        # handle API errors cleanly
        if jq -e '.error' >/dev/null 2>&1 <<<"$resp"; then
            local code msg
            code="$(jq -r '.error.code // empty' <<<"$resp")"
            msg="$(jq -r '.error.message // empty' <<<"$resp")"
            echo -e "${RED}Error from testIamPermissions:${NC} ${msg:-unknown} (code ${code:-?})" >&2
            return 3
        fi

        mapfile -t granted_batch < <(jq -r '.permissions[]?' <<<"$resp")
        # mark any not returned as missing
        local p had g
        for p in "${batch[@]}"; do
            had=""
            for g in "${granted_batch[@]}"; do
            [[ "$p" == "$g" ]] && { had=1; break; }
            done
            [[ -z "$had" ]] && missing+=("$p")
        done
        return 0
    }

    # run in batches (keep comfortably under body limits)
    local i step=90
    for ((i=0; i<${#req_perms[@]}; i+=step)); do
        _test_org_batch "${req_perms[@]:i:step}" || { echo "Permission probe failed." >&2; return 2; }
    done
    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options: " 
    (( audts == 0 )) && echo " - Audit Log Collection disabled" || echo " - Audit Log Collection enabled"
    echo
    echo "Scope: organizations/${ORG_NUM}"
    echo
    if ((${#missing[@]} == 0)); then
        echo -e "${GREEN}Permissions OK${NC} — all required GCP organization permissions are granted."
        printf ' - %s\n' "${req_perms[@]}"
        echo
        echo "You can onboard this GCP organization to Cortex Cloud."
        return 0
    else
        echo -e "${RED}Missing organization permissions:${NC}"
        printf ' - %s\n' "${missing[@]}"
        return 1
    fi
}

provider=""

# # Parse flags
# while getopts ":p:h" opt; do
#     case "$opt" in
#         p) provider="$OPTARG" ;;
#         h) usage; exit 0 ;;
#         :) echo "Missing argument for -$OPTARG" >&2; usage; exit 1 ;;
#         \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 1 ;;
#     esac
# done
# shift $((OPTIND-1))

# # If no flag was used -p, sking flag
# if [[ -z "$provider" ]]; then
#     read -rp "Choose provider (aws-account/aws-org/azure-sub/azure-mg/azure-tenant/gcp-project/gcp-org): " provider
# fi

# # Normalizing in lowercase
# provider="$(tr '[:upper:]' '[:lower:]' <<<"$provider")"

print_header "Preflight Permissions Check Menu"
echo
while :; do
    cat <<'MENU'
Please select the Account Type:
    1) AWS Account
    2) AWS Organization
    3) Azure Subscription
    4) Azure Management Group
    5) Azure Tenant
    6) GCP Project
    7) GCP Organization
MENU
    read -r -p "Enter choice [1-7]: " choice
    if [[ "$choice" =~ ^[1-7]$ ]]; then
        break
    else
        echo "Invalid choice. Please enter a number 1–7."
    fi
done

# Cases based on provider
case "$choice" in
    1)
        aws_account_check
        ;;
    2)
        aws_organization_check
        ;; 
    3)
        azure_subscription_check
        ;;
    4)
        azure_management_group_check
        ;;
    5)
        azure_tenant_check
        ;;
    6)
        gcp_project_check
        ;;
    7)
        gcp_org_check
        ;;
    *)
        echo "Invalid provider: $provider" >&2
        exit 1
        ;;
esac
