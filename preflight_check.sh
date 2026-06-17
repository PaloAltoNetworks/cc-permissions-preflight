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
BOLD='\033[1m'

#handle Azure errors
# Result buckets
PASSES=()
WARNINGS=()
ERRORS=()

log_pass() {
    PASSES+=("$1")
}

log_warning() {
    WARNINGS+=("$1")
}

log_error() {
    ERRS_MSG="$1"
    ERRORS+=("$ERRS_MSG")
}

has_errors() {
    [ "${#ERRORS[@]}" -gt 0 ]
}

print_final_summary() {
    echo
    print_header "Final Preflight Summary"
    echo

    if [ "${#ERRORS[@]}" -gt 0 ]; then
        echo -e "${RED}Blocking failures:${NC}"
        for err in "${ERRORS[@]}"; do
            echo -e "  ❌ $err"
        done
        echo
    fi

    if [ "${#WARNINGS[@]}" -gt 0 ]; then
        echo -e "${YELLOW}Warnings / advisory findings:${NC}"
        for warn in "${WARNINGS[@]}"; do
            echo -e "  ⚠️  $warn"
        done
        echo
    fi

    if [ "${#PASSES[@]}" -gt 0 ]; then
        echo -e "${GREEN}Successful checks:${NC}"
        for pass in "${PASSES[@]}"; do
            echo -e "  ✅ $pass"
        done
        echo
    fi

    if has_errors; then
        echo -e "${RED}🔴 VALIDATION FAILED:${NC} Required permissions are missing or a blocking prerequisite failed."
        echo -e "${YELLOW}Please fix the blocking failures above and re-run the script.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ VALIDATION PASSED:${NC} Required permissions are present."

    if [ "${#WARNINGS[@]}" -gt 0 ]; then
        echo -e "${YELLOW}Review the warnings above before onboarding.${NC}"
    fi

    exit 0
}

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
    local pat str
    pat="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    str="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
    [[ "$str" == $pat ]]
}

# Break-word for big infos
say() {
  echo -e "$@" | fold -s -w 75
}

read_lines_into_array() {
    local __array_name="$1"
    local __line
    eval "$__array_name=()"

    while IFS= read -r __line; do
        [ -n "$__line" ] && eval "$__array_name+=(\"\$__line\")"
    done
}

validate_azure_login() {
    if ! command -v az >/dev/null 2>&1; then
        echo -e "${RED}❌ Azure CLI not found.${NC}"
        log_error "Azure CLI is not installed or not available in PATH."
        return 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}❌ jq not found.${NC}"
        log_error "jq is required but not installed."
        return 1
    fi

    if ! az account show >/dev/null 2>&1; then
        echo -e "${RED}❌ Not logged in to Azure.${NC}"
        log_error "Azure CLI is not logged in. Run az login and try again."
        return 1
    fi

    local sub_id tenant_id user_name
    sub_id="$(az account show --query id -o tsv 2>/dev/null)"
    tenant_id="$(az account show --query tenantId -o tsv 2>/dev/null)"
    user_name="$(az account show --query user.name -o tsv 2>/dev/null)"

    log_pass "Azure CLI login detected. User: $user_name, Tenant: $tenant_id, Subscription: $sub_id"
    return 0
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
    "Microsoft.Authorization/roleAssignments/read"
    "Microsoft.Authorization/roleAssignments/write"
    "Microsoft.Authorization/roleAssignments/delete"
    "Microsoft.Authorization/roleDefinitions/read"
    "Microsoft.Authorization/roleDefinitions/write"
    "Microsoft.Authorization/roleDefinitions/delete"
    "Microsoft.Authorization/roleManagementPolicies/read"
    "Microsoft.Authorization/roleManagementPolicies/write"
    "Microsoft.Authorization/roleManagementPolicyAssignments/read"
    "Microsoft.Resources/deployments/validate/action"
    "Microsoft.Insights/DiagnosticSettings/Write"
    "Microsoft.Resources/deployments/read"
    "Microsoft.Resources/deployments/write"
    "Microsoft.Resources/deployments/delete"
    "Microsoft.Resources/deployments/cancel/action"
    "Microsoft.Resources/deployments/whatIf/action"
    "Microsoft.Resources/deployments/operations/read"
    "Microsoft.Resources/deployments/exportTemplate/action"
    "Microsoft.Resources/deployments/operationstatuses/read"
    "Microsoft.PolicyInsights/remediations/read"
    "Microsoft.PolicyInsights/remediations/write"
    "Microsoft.PolicyInsights/remediations/delete"
    "Microsoft.PolicyInsights/remediations/cancel/action"
    "Microsoft.PolicyInsights/remediations/listDeployments/read"
    "Microsoft.Resources/subscriptions/read"
    "Microsoft.ContainerInstance/containerGroups/read"
    "Microsoft.Storage/storageAccounts/read"
    "Microsoft.Storage/storageAccounts/write"
    "Microsoft.ContainerInstance/containerGroups/write"
    "Microsoft.ManagedIdentity/userAssignedIdentities/write"
    "Microsoft.ManagedIdentity/userAssignedIdentities/read"
    "Microsoft.Management/managementGroups/read"
    "Microsoft.Authorization/policyAssignments/read"
    "Microsoft.Authorization/policyAssignments/write"
    "Microsoft.Authorization/policyDefinitions/read"
    "Microsoft.Authorization/policySetDefinitions/read"
    "Microsoft.PolicyInsights/policyStates/summarize/action"
    "Microsoft.PolicyInsights/policyStates/queryResults/action"
    "Microsoft.Authorization/policyDefinitions/write"
    "Microsoft.Insights/diagnosticSettings/read"
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
    "Microsoft.Management/managementGroups/descendants/read"
    "Microsoft.Management/managementGroups/subscriptions/read"
    "Microsoft.Resources/deployments/*"
    "Microsoft.Resources/subscriptions/resourceGroups/*"
    "Microsoft.Resources/subscriptions/read"
    "Microsoft.Authorization/roleDefinitions/*"
    "Microsoft.Authorization/roleAssignments/*"
    "Microsoft.Authorization/policyDefinitions/*"
    "Microsoft.Authorization/policyAssignments/*"
    "Microsoft.EventHub/namespaces/*"
    "Microsoft.Insights/diagnosticSettings/*"
    "Microsoft.Compute/galleries/*"
)
PERMISSIONS_AZURE_MG_AUDIT_LOGS=(
    "Microsoft.Resources/subscriptions/resourcegroups/read"
    "Microsoft.Resources/subscriptions/resourcegroups/write"
    "Microsoft.Resources/subscriptions/resourceGroups/delete"
    "Microsoft.Resources/subscriptions/resourceGroups/moveResources/action"
    "Microsoft.Resources/subscriptions/resourceGroups/validateMoveResources/action"
    "Microsoft.Resources/deploymentScripts/write"
    "Microsoft.Resources/deploymentScripts/read"
    "Microsoft.Resources/deploymentScripts/delete"
    "Microsoft.EventHub/namespaces/write"
    "Microsoft.EventHub/namespaces/eventhubs/write"
    "Microsoft.EventHub/namespaces/authorizationRules/write"
    "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/write"
    "Microsoft.EventHub/namespaces/eventhubs/consumergroups/write"
    "Microsoft.Storage/storageAccounts/blobServices/write"
    "Microsoft.EventHub/namespaces/read"
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

    echo "Are you enabling - Collect Audit Logs (CloudTrail)?"
    read -p "Enter your choice of yes or no (y or n): " audit_logs
    case $audit_logs in
        y|Y)
            aws_single_actions+=("${PERMISSIONS_AWS_ACCOUNT_AUDIT_LOGS[@]}")
            audts=1
            ;;
    esac

    echo 
    echo "Are you enabling at least one of the following features?"
    echo " - Data security posture management"
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
    (( audts == 0 )) && echo "- Audit Logs disabled" || echo "Audit Logs enabled"
    (( feats == 0 )) && echo "- DSPM, Registry Scanning and Serverless function scanning disabled." || echo "DSPM, Registry Scanning or/and Serverless function Scanning enabled."
    echo
    echo "- Identity ARN: $IDENTITY_ARN"
    echo "- ACCOUNT ID: $ACCOUNT_ID"
    echo
    if [ ${#DENIED_ACTIONS[@]} -eq 0 ]; then
        echo -e "${GREEN}You have the required permissions.${NC}"
    else
        echo -e "${RED} Missing permissions:${NC}"
        for PERM in "${DENIED_ACTIONS[@]}"; do
            echo "   - $PERM"
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
        echo "- organizations:DescribeOrganization"
        echo "- organizations:DescribeOrganizationalUnit"
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
        echo "Detected CloudShell root ARN — All permission are satisfied"
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

    echo "Are you enabling - Collect Audit Logs (CloudTrail)?"
    read -p "Enter your choice of yes or no (y or n): " audit_logs
    case $audit_logs in
        y|Y)
            aws_org_actions=("${PERMISSIONS_AWS_ORG_BASE[@]}" "${PERMISSIONS_AWS_ORG_AUDIT_LOGS[@]}")
            audts=1
            ;;
        n|N)
            aws_org_actions=("${PERMISSIONS_AWS_ORG_BASE[@]}")
            ;;
        *)
            aws_org_actions=("${PERMISSIONS_AWS_ORG_BASE[@]}")
            ;;
    esac

    echo 
    echo "Are you enabling at least one of the following features?"
    echo " - Data security posture management"
    echo " - Registry scanning"
    echo " - Serverless function scanning"

    read -p "Enter your choice of yes or no (y or n): " aws_features

    case $aws_features in
        y|Y)
            aws_org_actions=("${aws_org_actions[@]}" "${PERMISSIONS_AWS_ORG_FEATURES[@]}")
            feats=1
            ;;
        n|N)
            ;;
    esac

    # Check each action
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
    (( audts == 0 )) && echo "- Audit Logs disabled" || echo "Audit Logs enabled"
    (( feats == 0 )) && echo "- DSPM, Registry Scanning and Serverless function scanning disabled." || echo "DSPM, Registry Scanning or/and Serverless function Scanning enabled."
    echo
    echo "- Identity ARN: $IDENTITY_ARN"
    echo "- ACCOUNT ID: $ACCOUNT_ID"
    echo "- Organization Master ACCOUNT ID: $ORG_ID"
    echo
    echo "Make sure these services are active in your AWS Organization:"
    echo "- AWS Account Management"
    echo "- AWS CloudFormation StackSets"
    echo "- CloudTrail"
    echo
    echo "Make sure you have a service-linked role for CloudTrail."

    if [ ${#DENIED_ACTIONS[@]} -eq 0 ]; then
        echo -e "${GREEN}You have the required permissions.${NC}"
    else
        echo -e "${RED}Missing permissions:${NC}"
        for PERM in "${DENIED_ACTIONS[@]}"; do
            echo "   - $PERM"
        done
        echo 
        echo "Please contact an administrator to enable those permissions."
    fi
}

validate_management_group_input() {
    echo
    print_header "Azure Management Group Input"
    echo

    if [ -z "$MANAGEMENT_GROUP_ID" ]; then
        read -rp "Enter Management Group ID: " MANAGEMENT_GROUP_ID
    fi

    MANAGEMENT_GROUP_ID="$(echo "$MANAGEMENT_GROUP_ID" | xargs)"

    if [ -z "$MANAGEMENT_GROUP_ID" ]; then
        echo -e "${RED}❌ ERROR: Management Group ID cannot be empty.${NC}"
        log_error "Management Group ID not provided."
        return 1
    fi

    if [[ ! "$MANAGEMENT_GROUP_ID" =~ ^[a-zA-Z0-9._()-]+$ ]]; then
        echo -e "${RED}❌ ERROR: Invalid Management Group ID format.${NC}"
        log_error "Invalid Management Group ID format: $MANAGEMENT_GROUP_ID"
        return 1
    fi

    if ! az account management-group show --name "$MANAGEMENT_GROUP_ID" -o none 2>/dev/null; then
        echo -e "${RED}❌ ERROR: Management Group '$MANAGEMENT_GROUP_ID' does not exist or you lack permissions.${NC}"
        log_error "Management Group '$MANAGEMENT_GROUP_ID' not found or inaccessible."
        return 1
    fi

    log_pass "Management Group '$MANAGEMENT_GROUP_ID' exists and is accessible."
    return 0
}

azure_management_group_policy_check() {
    echo
    print_header "Starting Azure Management Group Cortex Policy Validation"
    echo

    if [ -z "$MANAGEMENT_GROUP_ID" ]; then
        echo -e "${YELLOW}⚠️ MANAGEMENT_GROUP_ID is not set. Skipping Cortex policy validation.${NC}"
        log_warning "Skipped Cortex Management Group Policy validation because MANAGEMENT_GROUP_ID is not set."
        return 0
    fi

    MANAGEMENT_GROUP_SCOPE="/providers/Microsoft.Management/managementGroups/${MANAGEMENT_GROUP_ID}"

    echo "Target Management Group: $MANAGEMENT_GROUP_ID"
    echo "--------------------------------------------------"
    echo "1. Searching for Cortex policy assignment..."

    ASSIGNMENT_JSON=$(az policy assignment list \
        --scope "$MANAGEMENT_GROUP_SCOPE" \
        --query "[?contains(displayName, 'Cortex')].[id, displayName]" \
        --output tsv 2>/dev/null)

    MATCH_COUNT=$(echo "$ASSIGNMENT_JSON" | grep -c '.' || true)

    if [ "$MATCH_COUNT" -eq 0 ] || [ -z "$ASSIGNMENT_JSON" ]; then
        echo -e "${YELLOW}⚠️ No Cortex policy assignment found.${NC}"
        log_warning "Cortex policy assignment was not found at Management Group '$MANAGEMENT_GROUP_ID'. This may be expected before onboarding or before the Cortex policy assignment exists."
        return 0
    fi

    if [ "$MATCH_COUNT" -gt 1 ]; then
        echo -e "${YELLOW}⚠️ Multiple Cortex-like policy assignments found. Using first match for compliance check.${NC}"
        log_warning "Multiple Cortex-like policy assignments found at Management Group '$MANAGEMENT_GROUP_ID'. Script used the first match."
    fi

    ASSIGNMENT_ID=$(echo "$ASSIGNMENT_JSON" | head -1 | cut -f1)
    ASSIGNMENT_NAME=$(echo "$ASSIGNMENT_JSON" | head -1 | cut -f2)

    echo -e "   ${GREEN}→ Found:${NC} $ASSIGNMENT_NAME"
    echo -e "   ${GREEN}→ ID:${NC}    $ASSIGNMENT_ID"
    echo

    echo "2. Checking compliance state..."

    NON_COMPLIANT_RESOURCES=$(az policy state list \
        --management-group "$MANAGEMENT_GROUP_ID" \
        --filter "policyAssignmentId eq '$ASSIGNMENT_ID'" \
        --query "[?complianceState=='NonCompliant'].resourceId" \
        --output tsv 2>/dev/null)

    if [ -z "$NON_COMPLIANT_RESOURCES" ]; then
        echo -e "${GREEN}✅ Cortex policy assignment is compliant.${NC}"
        log_pass "Cortex policy assignment '$ASSIGNMENT_NAME' is compliant."
        return 0
    fi

    NON_COMPLIANT_COUNT=$(echo "$NON_COMPLIANT_RESOURCES" | wc -l | xargs)

    echo -e "${YELLOW}⚠️ Cortex policy assignment is non-compliant.${NC}"
    echo "   → Found $NON_COMPLIANT_COUNT non-compliant resource(s)"
    echo
    echo "Non-compliant resources:"
    echo "$NON_COMPLIANT_RESOURCES"

    log_warning "Cortex policy assignment '$ASSIGNMENT_NAME' has $NON_COMPLIANT_COUNT non-compliant resource(s). Remediation may be required, but this script is notify-only."

    return 0
}

azure_conditional_access_policy_check() {
    echo
    print_header "Starting Azure Conditional Access Policy Check"
    echo

    local GRAPH_URL="https://graph.microsoft.com/v1.0"
    local GRAPH_RESOURCE="https://graph.microsoft.com"
    local ARM_ID="797f4846-ba00-4fd7-ba43-dac1f87f440d"
    local CLOUD_SHELL_ID="2233b157-f44d-4812-b777-036cdaf9a96e"

    if ! command -v az >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️ Azure CLI or jq is missing. Skipping Conditional Access check.${NC}"
        log_warning "Skipped Conditional Access check because Azure CLI or jq is missing."
        return 0
    fi

    if ! az account show >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️ Not logged in to Azure. Skipping Conditional Access check.${NC}"
        log_warning "Skipped Conditional Access check because Azure CLI is not logged in."
        return 0
    fi

    echo "1. Retrieving Microsoft Graph token via Azure CLI"

    TOKEN=$(az account get-access-token \
        --resource "$GRAPH_RESOURCE" \
        --query accessToken \
        -o tsv 2>/dev/null)

    if [ -z "$TOKEN" ]; then
        echo -e "${YELLOW}⚠️ Failed to retrieve Microsoft Graph token.${NC}"
        log_warning "Unable to retrieve Microsoft Graph token. Conditional Access policies could not be evaluated."
        return 0
    fi

    USER_INFO=$(az account show --query "{tenantId:tenantId, user:user.name}" -o json 2>/dev/null)
    CURRENT_USER=$(echo "$USER_INFO" | jq -r '.user')
    CURRENT_TENANT=$(echo "$USER_INFO" | jq -r '.tenantId')

    echo
    echo "2. Fetching Conditional Access policies from Microsoft Graph"

    ERROR_OUTPUT_FILE="$(mktemp)"

    RAW_POLICIES_JSON=$(az rest \
        --method GET \
        --url "${GRAPH_URL}/identity/conditionalAccess/policies" \
        --headers "Authorization=Bearer ${TOKEN}" \
        --query 'value' \
        -o json 2>"$ERROR_OUTPUT_FILE")

    REST_STATUS=$?
    ERROR_OUTPUT="$(cat "$ERROR_OUTPUT_FILE" 2>/dev/null)"
    rm -f "$ERROR_OUTPUT_FILE"

    if [ "$REST_STATUS" -ne 0 ] || [ -z "$RAW_POLICIES_JSON" ]; then
        echo -e "${YELLOW}⚠️ Unable to read Conditional Access policies.${NC}"
        echo
        echo -e "${YELLOW}Current User Context:${NC}"
        echo "  User: $CURRENT_USER"
        echo "  Tenant ID: $CURRENT_TENANT"

        if [ -n "$ERROR_OUTPUT" ]; then
            echo
            echo "Graph error snippet:"
            echo "$ERROR_OUTPUT" | head -c 500
            echo
        fi

        log_warning "Unable to read Conditional Access policies. User may need Global Reader, Security Reader, Security Administrator, Conditional Access Administrator, or a refreshed PIM/Azure CLI token."
        return 0
    fi

    if [ "$RAW_POLICIES_JSON" = "[]" ]; then
        echo -e "${GREEN}✅ Successfully read Conditional Access policies. Found 0 policies.${NC}"
        log_pass "Conditional Access policies were readable. Found 0 policies."
        return 0
    fi

    ONBOARDING_POLICIES=$(echo "$RAW_POLICIES_JSON" | jq --arg ARM_ID "$ARM_ID" --arg CLOUD_SHELL_ID "$CLOUD_SHELL_ID" '
        map(select(.state == "enabled")) |
        map({
            displayName: .displayName,
            state: .state,
            builtInControls: ((.grantControls.builtInControls // []) | join(", ")),
            clientAppTypes: ((.conditions.clientAppTypes // []) | join(", ")),
            relevantAppIds: (
                (.conditions.applications.includeApplications // []) |
                map(if type == "object" then .id else . end) |
                map(select(. == $ARM_ID or . == $CLOUD_SHELL_ID))
            )
        }) |
        map(select((.relevantAppIds | length) > 0))
    ')

    COUNT=$(echo "$ONBOARDING_POLICIES" | jq '. | length')

    if [ "$COUNT" -gt 0 ]; then
        echo -e "${YELLOW}⚠️ Conditional Access policies may impact onboarding:${NC}"
        echo

        echo "$ONBOARDING_POLICIES" | jq -r '
            .[] |
            "  Name: \(.displayName)\n" +
            "  State: \(.state)\n" +
            "  Controls: \(.builtInControls)\n" +
            "  Client Apps: \(.clientAppTypes)\n" +
            "  Targeted App IDs: \(.relevantAppIds | join(", "))\n"
        '

        log_warning "$COUNT enabled Conditional Access policy/policies target Azure Resource Manager or Cloud Shell and may impact onboarding."
    else
        echo -e "${GREEN}✅ No enabled Conditional Access policies found targeting ARM or Cloud Shell.${NC}"
        log_pass "Conditional Access policies were readable and no direct ARM/Cloud Shell impact was detected."
    fi

    return 0
}

azure_resource_provider_check() {
    echo
    print_header "Starting Azure Resource Provider Registration Check"
    echo

    echo -e "${YELLOW}NOTE:${NC} This script does not register providers. It only reports provider registration state."
    echo

    local PROVIDERS_TO_CHECK=(
        "Microsoft.Security"
        "Microsoft.Insights"
        "Microsoft.Communication"
        "Microsoft.Datadog"
        "Microsoft.Aadiam"
    )

    local CURRENT_SUBSCRIPTION
    CURRENT_SUBSCRIPTION=$(az account show --query "id" --output tsv 2>/dev/null)

    if [ -z "$CURRENT_SUBSCRIPTION" ]; then
        echo -e "${YELLOW}⚠️ Unable to retrieve current Azure subscription.${NC}"
        log_warning "Unable to retrieve Azure subscription for provider registration check."
        return 0
    fi

    echo "Using subscription: $CURRENT_SUBSCRIPTION"
    echo

    local FAILED_PROVIDERS=()

    for provider in "${PROVIDERS_TO_CHECK[@]}"; do
        echo -n "Checking provider: $provider ... "

        STATE=$(az provider show \
            --namespace "$provider" \
            --query "registrationState" \
            --output tsv 2>/dev/null)

        case "$STATE" in
            Registered)
                echo -e "${GREEN}✅ Registered${NC}"
                ;;
            Registering)
                echo -e "${YELLOW}⚠️ Registering${NC}"
                FAILED_PROVIDERS+=("$provider (Status: Registering)")
                ;;
            NotRegistered|Unregistered)
                echo -e "${YELLOW}⚠️ Not Registered${NC}"
                echo -e "   Suggested action: ${BOLD}az provider register --namespace $provider --subscription $CURRENT_SUBSCRIPTION${NC}"
                FAILED_PROVIDERS+=("$provider (Status: Not Registered)")
                ;;
            *)
                echo -e "${YELLOW}⚠️ Unknown State: ${STATE:-No response}${NC}"
                FAILED_PROVIDERS+=("$provider (Status: Unknown - ${STATE:-No response})")
                ;;
        esac
    done

    echo

    if [ "${#FAILED_PROVIDERS[@]}" -eq 0 ]; then
        echo -e "${GREEN}✅ All checked providers are registered.${NC}"
        log_pass "All checked Azure resource providers are registered."
    else
        echo -e "${YELLOW}⚠️ Provider registration warnings:${NC}"
        for p in "${FAILED_PROVIDERS[@]}"; do
            echo -e "   - $p"
        done

        log_warning "Some Azure resource providers need attention: ${FAILED_PROVIDERS[*]}"
    fi

    return 0
}

azure_subscription_check() {
    echo
    print_header "Starting Azure Subscription Preflight"
    echo

    validate_azure_login || print_final_summary

    # Advisory checks only. These should not fail the script.
    azure_resource_provider_check
    azure_conditional_access_policy_check

    echo
    print_header "Starting Azure Subscription Preflight Permissions Check"
    echo
    echo "Note: Some delete permissions are included for rollback. They're not required for onboarding."
    echo

    # deps
    command -v az >/dev/null || { log_error "az CLI not found"; print_final_summary; }
    command -v jq >/dev/null || { log_error "jq not found"; print_final_summary; }

    # scope
    local SUBSCRIPTION_ID SCOPE ASSIGNEE
    SUBSCRIPTION_ID="$(az account show --query id -o tsv 2>/dev/null)" || {
        log_error "Cannot get Azure subscription ID."
        print_final_summary
    }
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
        read_lines_into_array _a   < <(jq -r '.permissions[]?.actions[]?'         <<<"$role")
        read_lines_into_array _na  < <(jq -r '.permissions[]?.notActions[]?'      <<<"$role")
        read_lines_into_array _da  < <(jq -r '.permissions[]?.dataActions[]?'     <<<"$role")
        read_lines_into_array _nda < <(jq -r '.permissions[]?.notDataActions[]?'  <<<"$role")
        EFFECTIVE_ACTIONS+=("${_a[@]}");   EFFECTIVE_NOTACTIONS+=("${_na[@]}")
        EFFECTIVE_DATAACTIONS+=("${_da[@]}"); EFFECTIVE_NOTDATAACTIONS+=("${_nda[@]}")
    done <<<"$role_ids"

    # de-dup
    read_lines_into_array EFFECTIVE_ACTIONS        < <(printf "%s\n" "${EFFECTIVE_ACTIONS[@]}"        | awk 'NF' | sort -u)
    read_lines_into_array EFFECTIVE_NOTACTIONS     < <(printf "%s\n" "${EFFECTIVE_NOTACTIONS[@]}"     | awk 'NF' | sort -u)
    read_lines_into_array EFFECTIVE_DATAACTIONS    < <(printf "%s\n" "${EFFECTIVE_DATAACTIONS[@]}"    | awk 'NF' | sort -u)
    read_lines_into_array EFFECTIVE_NOTDATAACTIONS < <(printf "%s\n" "${EFFECTIVE_NOTDATAACTIONS[@]}" | awk 'NF' | sort -u)

    # wildcard matcher: allow patterns like Microsoft.*/*/read
    _match() { local pat="$1" str="$2"; [[ "$str" == $pat ]]; }

    echo "Are you enabling - Collect Audit Logs (CloudTrail)?"
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
    (( audts == 0 )) && echo "- Audit Logs disabled" || echo "Audit Logs enabled"
    echo
    echo "Assignee: $ASSIGNEE"
    echo "Scope:    $SCOPE"
    echo
    if (( ${#missing[@]} == 0 )); then
        echo -e "${GREEN}Actions OK${NC} all required actions are satisfied."
        printf '  - %s\n' "${azure_single_actions[@]}"
        echo
        echo "You can onboard this Azure subscription ($SUBSCRIPTION_ID) in Cortex Cloud"
        log_pass "Required Azure subscription permissions are present for subscription $SUBSCRIPTION_ID."
    else
        echo -e "${GREEN}You have the following required actions:${NC}"
        read_lines_into_array DIF < <(printf '%s\n' "${azure_single_actions[@]}" \
            | grep -Fxv -f <(printf '%s\n' "${missing[@]}"))
        printf '%s\n' "${DIF[@]}"
        echo
        echo -e "${RED}Missing permissions:${NC}"
        printf '  - %s\n' "${missing[@]}"
        log_error "Missing required Azure subscription permissions: ${missing[*]}"
    fi

    print_final_summary
}

azure_management_group_check() {
    echo
    print_header "Starting Azure Management Group Preflight"
    echo

    validate_azure_login || print_final_summary
    validate_management_group_input || print_final_summary

    # Advisory checks only. These should not fail the script.
    azure_management_group_policy_check
    azure_resource_provider_check
    azure_conditional_access_policy_check

    echo
    print_header "Starting Azure Management Group Preflight Permissions Check"
    echo
    echo "Note: Some delete permissions are included for rollback. They're not required for onboarding."
    echo

    # deps
    command -v az >/dev/null || { log_error "az CLI not found"; print_final_summary; }
    command -v jq >/dev/null || { log_error "jq not found"; print_final_summary; }

    # management group scope
    local MG_SCOPE ASSIGNEE

    MG_SCOPE="/providers/Microsoft.Management/managementGroups/${MANAGEMENT_GROUP_ID}"

    # current principal (objectId if possible, else UPN)
    ASSIGNEE="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
    [[ -z "$ASSIGNEE" ]] && ASSIGNEE="$(az account show --query user.name -o tsv 2>/dev/null || true)"
    [[ -n "$ASSIGNEE" ]] || { echo "❌ Cannot resolve current principal (objectId or UPN)" >&2; return 2; }

    # role assignments (MG scope + inherited + group-based)
    local assignments role_ids roles_json

    assignments="$(
        az role assignment list \
            --assignee "$ASSIGNEE" \
            --scope "$MG_SCOPE" \
            --include-inherited \
            --include-groups \
            -o json
    )" || { echo "❌ Failed to list role assignments at MG scope" >&2; return 2; }

    role_ids="$(jq -r '.[].roleDefinitionId' <<<"$assignments" | sort -u)"

    roles_json="$(az role definition list --scope "$MG_SCOPE" -o json)" \
        || { echo "❌ Failed to list role definitions at MG scope" >&2; return 2; }

    # build effective allow sets
    local EFFECTIVE_ACTIONS=() EFFECTIVE_NOTACTIONS=()
    local EFFECTIVE_DATAACTIONS=() EFFECTIVE_NOTDATAACTIONS=()

    while IFS= read -r rid; do
        [[ -z "$rid" ]] && continue

        rid_guid="${rid##*/}"

        role="$(jq -c --arg rid "$rid" --arg gid "$rid_guid" '
            .[] | select(
                .id == $rid
                or .name == $gid
                or (.id | endswith($gid))
            )' <<<"$roles_json")"

        [[ -z "$role" ]] && continue

        read_lines_into_array _a   < <(jq -r '.permissions[]?.actions[]?'        <<<"$role")
        read_lines_into_array _na  < <(jq -r '.permissions[]?.notActions[]?'     <<<"$role")
        read_lines_into_array _da  < <(jq -r '.permissions[]?.dataActions[]?'    <<<"$role")
        read_lines_into_array _nda < <(jq -r '.permissions[]?.notDataActions[]?' <<<"$role")

        EFFECTIVE_ACTIONS+=("${_a[@]}")
        EFFECTIVE_NOTACTIONS+=("${_na[@]}")
        EFFECTIVE_DATAACTIONS+=("${_da[@]}")
        EFFECTIVE_NOTDATAACTIONS+=("${_nda[@]}")
    done <<<"$role_ids"

    # Deduplicate all sets
    read_lines_into_array EFFECTIVE_ACTIONS        < <(printf "%s\n" "${EFFECTIVE_ACTIONS[@]}"        | awk 'NF' | sort -u)
    read_lines_into_array EFFECTIVE_NOTACTIONS     < <(printf "%s\n" "${EFFECTIVE_NOTACTIONS[@]}"     | awk 'NF' | sort -u)
    read_lines_into_array EFFECTIVE_DATAACTIONS    < <(printf "%s\n" "${EFFECTIVE_DATAACTIONS[@]}"    | awk 'NF' | sort -u)
    read_lines_into_array EFFECTIVE_NOTDATAACTIONS < <(printf "%s\n" "${EFFECTIVE_NOTDATAACTIONS[@]}" | awk 'NF' | sort -u)

    _is_mg_root() {
        local s mg
        s="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
        mg="/providers/microsoft.management/managementgroups/$(printf '%s' "$MANAGEMENT_GROUP_ID" | tr '[:upper:]' '[:lower:]')"
        [[ "$s" == "$mg" ]]
    }
    # Deny assignments at MG scope (can block even if a role allows)
    local denies
    denies="$(
        az rest --method get \
            --url "https://management.azure.com${MG_SCOPE}/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01&%24filter=atScope()" \
            -o json || true
    )"

    declare -a EFFECTIVE_DENY_ACTIONS_SCOPED=()
    declare -a EFFECTIVE_DENY_DATAACTIONS_SCOPED=()

    # Only include deny assignments that actually apply to the current assignee.
    # This prevents unrelated Azure/system/managed-app deny assignments from falsely blocking this user.
    read_lines_into_array EFFECTIVE_DENY_ACTIONS_SCOPED < <(
        jq -r --arg assignee "$ASSIGNEE" '
            .value[]?
            | select(.properties.scope != null)
            | select(
                (
                    [.properties.principals[]?.id] | index($assignee)
                )
                or
                (
                    [.properties.principals[]?.id] | index("00000000-0000-0000-0000-000000000000")
                )
            )
            | select(
                ([.properties.excludePrincipals[]?.id] | index($assignee)) | not
            )
            | "\(.properties.scope)|\(.properties.permissions[]?.denyActions[]?)"
        ' <<<"$denies"
    )

    read_lines_into_array EFFECTIVE_DENY_DATAACTIONS_SCOPED < <(
        jq -r --arg assignee "$ASSIGNEE" '
            .value[]?
            | select(.properties.scope != null)
            | select(
                (
                    [.properties.principals[]?.id] | index($assignee)
                )
                or
                (
                    [.properties.principals[]?.id] | index("00000000-0000-0000-0000-000000000000")
                )
            )
            | select(
                ([.properties.excludePrincipals[]?.id] | index($assignee)) | not
            )
            | "\(.properties.scope)|\(.properties.permissions[]?.denyDataActions[]?)"
        ' <<<"$denies"
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
    echo "Enable additional audit/diagnostics permissions for MG (if required)?"
    read -rp "Answer y/n: " mg_audit
    case "$mg_audit" in
        y|Y) azure_mg_required+=("${PERMISSIONS_AZURE_MG_AUDIT_LOGS[@]}"); audts=1 ;;
    esac

    # de-dup required
    read_lines_into_array azure_mg_required < <(printf "%s\n" "${azure_mg_required[@]}" | awk 'NF' | sort -u)

    # evaluate
    local missing=()

    for req in "${azure_mg_required[@]}"; do
        [[ -z "$req" ]] && continue

        # blocked by Deny?
        if _blocked_at_mg "$req"; then
            missing+=("$req (blocked by Deny at MG)")
            continue
        fi

        # allowed?
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
    (( audts == 0 )) && echo "- Audit Logs disabled" || echo "Audit Logs enabled"
    echo
    echo "Assignee: $ASSIGNEE"
    echo "Management Group Scope: $MG_SCOPE"
    echo 
    if (( ${#missing[@]} == 0 )); then
        (( audts == 0 )) && echo "" || echo "Make sure you have Global Administrator role assigned in Entra ID instance to onboard this Management Group in Cortex Cloud"
        echo
        echo -e "${GREEN}Permissions OK${NC} — all required entries for MG scope are satisfied."
        printf '  - %s\n' "${azure_mg_required[@]}"
        log_pass "Required Azure Management Group permissions are present at $MG_SCOPE."
    else
        (( audts == 0 )) && echo "" || echo "Make sure you have Global Administrator role assigned in Entra ID instance to onboard this Management Group in Cortex Cloud"
        echo
        echo -e "${RED}Missing permissions at MG scope:${NC}"
        printf '  - %s\n' "${missing[@]}"
        log_error "Missing required Azure Management Group permissions at $MG_SCOPE: ${missing[*]}"
    fi

    print_final_summary
}

azure_tenant_check() {
    echo
    print_header "Starting Azure Tenant Preflight"
    echo

    validate_azure_login || print_final_summary

    # Advisory checks only. These should not fail the script.
    azure_resource_provider_check
    azure_conditional_access_policy_check

    echo
    print_header "Checking Entra ID role: Global Administrator"
    echo

    command -v az >/dev/null || {
        echo -e "${RED}az CLI not found${NC}" >&2
        log_error "az CLI not found."
        print_final_summary
    }

    command -v jq >/dev/null || {
        echo -e "${RED}jq not found${NC}" >&2
        log_error "jq not found."
        print_final_summary
    }

    local TENANT_ID UPN OBJECT_ID
    TENANT_ID="${AZURE_TENANT_ID:-$(az account show --query tenantId -o tsv 2>/dev/null)}"

    if [[ -z "$TENANT_ID" ]]; then
        echo -e "${RED}Cannot resolve tenant ID.${NC}" >&2
        log_error "Cannot resolve Azure tenant ID."
        print_final_summary
    fi

    UPN="$(az account show --query user.name -o tsv 2>/dev/null || true)"
    OBJECT_ID="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"

    echo "Tenant:          $TENANT_ID"
    [[ -n "$UPN" ]] && echo "Signed-in UPN:    $UPN"
    [[ -n "$OBJECT_ID" ]] && echo "Signed-in Obj ID: $OBJECT_ID"
    echo

    if [[ -z "$OBJECT_ID" ]]; then
        echo -e "${RED}Cannot resolve signed-in user's object ID.${NC}"
        echo "Run: az login --tenant $TENANT_ID"
        log_error "Cannot resolve signed-in user's object ID. Tenant checks cannot be fully evaluated."
        print_final_summary
    fi

    # Microsoft Graph / Entra Global Administrator role template ID
    local GA_TEMPLATE_ID="62e90394-69f5-4237-9190-012177145e10"
    local roles_json role_id ga_role_error_file ga_member_error_file

    ga_role_error_file="$(mktemp)"

    roles_json="$(
        az rest \
            --resource "https://graph.microsoft.com" \
            --method GET \
            --url "https://graph.microsoft.com/v1.0/directoryRoles?\$filter=roleTemplateId%20eq%20'$GA_TEMPLATE_ID'" \
            -o json 2>"$ga_role_error_file"
    )"

    if [[ $? -ne 0 || -z "$roles_json" ]]; then
        echo -e "${RED}Failed to query Microsoft Graph for Global Administrator role.${NC}"
        echo "Tip: If you recently activated PIM, run: az logout && az login --tenant $TENANT_ID"
        echo "Tip: The Azure CLI app may need delegated Graph consent such as Directory.Read.All or RoleManagement.Read.Directory."
        [[ -s "$ga_role_error_file" ]] && cat "$ga_role_error_file"
        rm -f "$ga_role_error_file"
        log_error "Unable to verify Global Administrator role because Microsoft Graph directoryRoles query failed."
        print_final_summary
    fi

    rm -f "$ga_role_error_file"

    if jq -e '.error' >/dev/null 2>&1 <<<"$roles_json"; then
        local graph_error
        graph_error="$(jq -r '.error.message' <<<"$roles_json")"
        echo -e "${RED}Graph error:${NC} $graph_error"
        log_error "Unable to verify Global Administrator role. Graph error: $graph_error"
        print_final_summary
    fi

    role_id="$(jq -r '.value[0].id // empty' <<<"$roles_json")"

    if [[ -z "$role_id" ]]; then
        echo -e "${RED}Global Administrator directory role is not activated or not readable in this tenant.${NC}"
        log_error "Global Administrator directory role was not found or could not be read in tenant $TENANT_ID."
        print_final_summary
    fi

    local payload check_resp
    payload="$(jq -n --arg rid "$role_id" '{ids:[$rid]}')"
    ga_member_error_file="$(mktemp)"

    check_resp="$(
        az rest \
            --resource "https://graph.microsoft.com" \
            --method POST \
            --url "https://graph.microsoft.com/v1.0/me/checkMemberObjects" \
            --headers "Content-Type=application/json" \
            --body "$payload" \
            -o json 2>"$ga_member_error_file"
    )"

    if [[ $? -ne 0 || -z "$check_resp" ]]; then
        echo -e "${RED}Failed to query Microsoft Graph for current user's Global Administrator membership.${NC}"
        echo "Tip: If you recently activated PIM, run: az logout && az login --tenant $TENANT_ID"
        echo "Tip: This typically requires Directory.Read.All or RoleManagement.Read.Directory delegated consent for the Azure CLI app."
        [[ -s "$ga_member_error_file" ]] && cat "$ga_member_error_file"
        rm -f "$ga_member_error_file"
        log_error "Unable to verify whether the signed-in user is Global Administrator."
        print_final_summary
    fi

    rm -f "$ga_member_error_file"

    if jq -e '.error' >/dev/null 2>&1 <<<"$check_resp"; then
        local graph_error
        graph_error="$(jq -r '.error.message' <<<"$check_resp")"
        echo -e "${RED}Graph error:${NC} $graph_error"
        log_error "Unable to verify Global Administrator membership. Graph error: $graph_error"
        print_final_summary
    fi

    if jq -e --arg rid "$role_id" '.value[]? | select(. == $rid)' >/dev/null 2>&1 <<<"$check_resp"; then
        echo -e "Result: ${GREEN}You ARE a Global Administrator in this tenant.${NC}"
        log_pass "Signed-in user is a Global Administrator in tenant $TENANT_ID."
    else
        echo -e "Result: ${RED}You are NOT a Global Administrator in this tenant.${NC}"
        echo "You cannot onboard the Azure tenant to Cortex Cloud."
        log_error "User is not a Global Administrator in tenant $TENANT_ID."
    fi

    echo
    print_header "Checking Tenant Root Group Management Group"
    echo

    local ROOTMG ROOT_MG_SCOPE
    ROOTMG="$(
        az account management-group list \
            --query "[?properties.details.parent==null].name | [0]" \
            -o tsv 2>/dev/null || true
    )"

    if [[ -z "$ROOTMG" ]]; then
        echo -e "${YELLOW}⚠️ Root Management Group was not found or is not visible.${NC}"
        echo "This may indicate missing permission to view Management Groups."
        log_warning "Root Management Group was not found or inaccessible. Management Group visibility could not be validated."
    else
        ROOT_MG_SCOPE="/providers/Microsoft.Management/managementGroups/$ROOTMG"

        echo -e "${GREEN}Root Management Group visible:${NC} $ROOTMG"
        echo "Scope: $ROOT_MG_SCOPE"
        log_pass "Root Management Group '$ROOTMG' is visible."

        echo
        print_header "Checking Azure RBAC Owner/Contributor at Tenant Root Group"
        echo

        local ROOT_MG_ROLES_JSON
        ROOT_MG_ROLES_JSON="$(
            az role assignment list \
                --assignee-object-id "$OBJECT_ID" \
                --scope "$ROOT_MG_SCOPE" \
                --include-inherited \
                --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" \
                -o json 2>/dev/null || true
        )"

        if jq -e 'length > 0' >/dev/null 2>&1 <<<"$ROOT_MG_ROLES_JSON"; then
            local assigned_root_mg_roles
            assigned_root_mg_roles="$(jq -r '[.[] | .roleDefinitionName] | unique | join(", ")' <<<"$ROOT_MG_ROLES_JSON")"

            echo -e "Result: ${GREEN}User has required Azure RBAC role(s) at Tenant Root Group: $assigned_root_mg_roles.${NC}"
            log_pass "User has Azure RBAC role(s) at Tenant Root Group '$ROOTMG': $assigned_root_mg_roles."
        else
            echo -e "Result: ${RED}User does NOT have Owner or Contributor at Tenant Root Group.${NC}"
            echo "Action: Assign Owner or Contributor to '${UPN:-this user}' at the Tenant Root Group management group if tenant-wide onboarding requires it."
            log_error "Missing Owner or Contributor assignment at Tenant Root Group '$ROOTMG' for ${UPN:-this user}."
        fi
    fi

    echo
    print_header "Checking Azure RBAC at tenant root scope (/)"
    echo

    local ROOT_SCOPE="/"

    echo "Checking User Access Administrator at tenant root scope: $ROOT_SCOPE"

    local UAA_JSON
    UAA_JSON="$(
        az role assignment list \
            --assignee-object-id "$OBJECT_ID" \
            --scope "$ROOT_SCOPE" \
            --include-inherited \
            --query "[?roleDefinitionName=='User Access Administrator']" \
            -o json 2>/dev/null || true
    )"

    if jq -e 'length > 0' >/dev/null 2>&1 <<<"$UAA_JSON"; then
        echo -e "Result: ${GREEN}User has User Access Administrator at tenant root scope (/).${NC}"
        log_pass "User has User Access Administrator at tenant root scope (/)."
    else
        echo -e "Result: ${YELLOW}User does not have User Access Administrator at tenant root scope (/).${NC}"
        echo "Action: A Global Administrator can enable Entra ID → Properties → Access management for Azure resources, then sign out/in."
        log_warning "User does not have User Access Administrator at tenant root scope (/). This may affect ability to assign Azure RBAC across the tenant."
    fi

    echo
    print_header "Checking Owner/Contributor at tenant root scope (/)"
    echo

    local TENANT_ROOT_ROLES_JSON
    TENANT_ROOT_ROLES_JSON="$(
        az role assignment list \
            --assignee-object-id "$OBJECT_ID" \
            --scope "$ROOT_SCOPE" \
            --include-inherited \
            --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" \
            -o json 2>/dev/null || true
    )"

    if jq -e 'length > 0' >/dev/null 2>&1 <<<"$TENANT_ROOT_ROLES_JSON"; then
        local assigned_tenant_root_roles
        assigned_tenant_root_roles="$(jq -r '[.[] | .roleDefinitionName] | unique | join(", ")' <<<"$TENANT_ROOT_ROLES_JSON")"

        echo -e "Result: ${GREEN}User has Owner/Contributor at tenant root scope (/): $assigned_tenant_root_roles.${NC}"
        log_pass "User has Owner/Contributor at tenant root scope (/): $assigned_tenant_root_roles."
    else
        echo -e "Result: ${YELLOW}User does not have Owner or Contributor at tenant root scope (/).${NC}"
        echo "This is usually not the same as the Tenant Root Group IAM screen in the Azure Portal."
        log_warning "User does not have Owner or Contributor at tenant root scope (/). This may be acceptable if required access exists at the Tenant Root Group management group."
    fi

    print_final_summary
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
    while IFS= read -r line; do
        req_perms+=("$line")
    done < <(printf '%s\n' "${req_perms[@]}" | awk 'NF' | sort -u)

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

        granted_batch=()
        while IFS= read -r line; do
            granted_batch+=("$line")
        done < <(jq -r '.permissions[]?' <<<"$resp")

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
    (( audts == 0 )) && echo "- Audit Logs disabled" || echo "Audit Logs enabled"
    echo
    echo "Scope:    $PROJECT_ID"
    echo
    if ((${#missing[@]} == 0)); then
        echo -e "${GREEN}Permissions OK${NC} — all required GCP project permissions are granted."
        printf '  - %s\n' "${req_perms[@]}"
        return 0
    else
        echo -e "${RED}Missing permissions:${NC}"
        printf '%s\n' "${missing[@]}" | sort -u | sed 's/^/ - /'
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

    # resolve organization id
    local ORG_ID ORG_NUM
    local -a _orgs
    ORG_ID="${GCP_ORG_ID:-}"

    if [[ -z "$ORG_ID" ]]; then
        _orgs=()
        while IFS= read -r line; do
            [[ -n "$line" ]] && _orgs+=("$line")
        done < <(gcloud organizations list --format="value(ID)" 2>/dev/null || true)

        if ((${#_orgs[@]} == 1)); then
            ORG_ID="${_orgs[0]}"
        else
            echo
            echo -e "${YELLOW}Could not auto-detect exactly one GCP Organization.${NC}"
            echo "Detected organizations: ${#_orgs[@]}"
            read -rp "Enter GCP Organization ID (numeric, e.g. 123456789012): " ORG_ID
        fi
    fi

    ORG_ID="$(echo "$ORG_ID" | xargs)"
    [[ -n "$ORG_ID" ]] || { echo "Empty organization id" >&2; return 2; }

    ORG_NUM="${ORG_ID#organizations/}"

    echo "Organization: organizations/${ORG_NUM}"
    echo "Account:      ${ACCOUNT}"
    echo

    # --- Organization Policy Check: constraints/iam.allowedPolicyMemberDomains ---
    echo "Checking org policy constraints/iam.allowedPolicyMemberDomains..."

    local ORG_POLICY_JSON ORG_POLICY_ERR
    ORG_POLICY_JSON="$(mktemp)"
    ORG_POLICY_ERR="$(mktemp)"

    if gcloud org-policies describe constraints/iam.allowedPolicyMemberDomains \
        --organization "${ORG_NUM}" \
        --format=json >"${ORG_POLICY_JSON}" 2>"${ORG_POLICY_ERR}"; then

        local _allowed_json _denied_json _all_values _has_restriction
        _allowed_json="$(jq -r '
            if (.spec and ((.spec.rules // []) | length > 0)) then
              [ .spec.rules[]? | .values.allowedValues[]? ] | unique
            elif .listPolicy then
              (.listPolicy.allowedValues // [])
            else
              []
            end
        ' "${ORG_POLICY_JSON}")"

        _denied_json="$(jq -r '
            if (.spec and ((.spec.rules // []) | length > 0)) then
              [ .spec.rules[]? | .values.deniedValues[]? ] | unique
            elif .listPolicy then
              (.listPolicy.deniedValues // [])
            else
              []
            end
        ' "${ORG_POLICY_JSON}")"

        _all_values="$(jq -r '
            if (.listPolicy and .listPolicy.allValues) then
              .listPolicy.allValues
            else
              empty
            end
        ' "${ORG_POLICY_JSON}")"

        _has_restriction=""

        if [[ -n "$_all_values" && "$_all_values" != "ALLOW" ]]; then
            _has_restriction=1
        fi

        if jq -e 'length > 0' <<<"$_allowed_json" >/dev/null 2>&1; then
            _has_restriction=1
        fi

        if jq -e 'length > 0' <<<"$_denied_json" >/dev/null 2>&1; then
            _has_restriction=1
        fi

        if [[ -n "$_has_restriction" ]]; then
            echo -e "${YELLOW}Note:${NC} Org Policy ${BOLD}constraints/iam.allowedPolicyMemberDomains${NC} is configured."

            if jq -e 'length > 0' <<<"$_allowed_json" >/dev/null 2>&1; then
                echo "  Allowed member domains:"
                jq -r '.[]' <<<"$_allowed_json" | sed 's/^/    - /'
            fi

            if jq -e 'length > 0' <<<"$_denied_json" >/dev/null 2>&1; then
                echo "  Denied member domains:"
                jq -r '.[]' <<<"$_denied_json" | sed 's/^/    - /'
            fi

            if [[ -n "$_all_values" && "$_all_values" != "ALLOW" ]]; then
                echo "  allValues: ${_all_values}"
            fi

            echo -e "${YELLOW}Warning:${NC} This policy may block onboarding between GCP and Cortex Cloud if required identities are not within the allowed domains."
            echo "          Consider temporarily relaxing the policy or adding the necessary domains during onboarding."
        else
            echo -e "${GREEN}Org Policy present but not restricting domains.${NC}"
        fi

    else
        echo -e "${YELLOW}Warning:${NC} Could not read constraints/iam.allowedPolicyMemberDomains."

        if [[ -s "${ORG_POLICY_ERR}" ]]; then
            echo "gcloud error:"
            head -c 1000 "${ORG_POLICY_ERR}"
            echo
        fi

        echo "Continuing with permission checks..."
    fi

    rm -f "${ORG_POLICY_JSON}" "${ORG_POLICY_ERR}"
    # --- End Organization Policy Check ---

    if ! gcloud organizations describe "organizations/${ORG_NUM}" >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning:${NC} Unable to describe organization. You may lack resourcemanager.organizations.get. Continuing with permission checks..."
    fi

    # build required permissions from predefined arrays
    local -a req_perms
    req_perms=("${PERMISSIONS_GCP_ORG_BASE[@]}")

    local audts=0
    echo "Enable additional org-level audit/diagnostics permissions (if required by your template)?"
    read -rp "Answer y/n: " audit_logs

    case "$audit_logs" in
        y|Y)
            req_perms+=("${PERMISSIONS_GCP_ORG_AUDIT_LOGS[@]}")
            audts=1
            ;;
    esac

    # de-dup + strip empties
    local -a req_perms_dedup=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && req_perms_dedup+=("$line")
    done < <(printf '%s\n' "${req_perms[@]}" | awk 'NF' | sort -u)
    req_perms=("${req_perms_dedup[@]}")

    if ((${#req_perms[@]} == 0)); then
        echo -e "${YELLOW}No GCP org permissions listed to check. Permission arrays are empty.${NC}"
        return 0
    fi

    # access token
    local ACCESS_TOKEN
    ACCESS_TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || {
        echo "Failed to get access token" >&2
        return 2
    }

    [[ -n "$ACCESS_TOKEN" ]] || {
        echo "Empty access token" >&2
        return 2
    }

    # function to call testIamPermissions in batches
    local -a missing=() granted_batch=()

    _test_org_batch() {
        local -a batch=("$@")
        local json_perms payload resp resource
        json_perms="$(printf '%s\n' "${batch[@]}" | jq -R . | jq -s .)"
        payload="$(jq -n --argjson perms "$json_perms" '{permissions:$perms}')"

        resource="https://cloudresourcemanager.googleapis.com/v1/organizations/${ORG_NUM}"

        resp="$(curl -sS -X POST \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "${resource}:testIamPermissions")" || return 3

        # handle API errors cleanly
        if jq -e '.error' >/dev/null 2>&1 <<<"$resp"; then
            local code msg
            code="$(jq -r '.error.code // empty' <<<"$resp")"
            msg="$(jq -r '.error.message // empty' <<<"$resp")"

            echo -e "${RED}Error from testIamPermissions:${NC} ${msg:-unknown} (code ${code:-?})" >&2

            if [[ "$code" == "403" || "$code" == "7" ]]; then
                missing+=("${batch[@]}")
                return 0
            fi

            return 3
        fi

        granted_batch=()
        while IFS= read -r line; do
            [[ -n "$line" ]] && granted_batch+=("$line")
        done < <(jq -r '.permissions[]?' <<<"$resp")

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

    # run in batches
    local i step=90
    for ((i=0; i<${#req_perms[@]}; i+=step)); do
        _test_org_batch "${req_perms[@]:i:step}" || {
            echo "Permission probe failed." >&2
            return 2
        }
    done

    echo
    print_header "Preflight Permissions Check Summary"
    echo
    echo "Based on the selected options:"
    (( audts == 0 )) && echo "- Audit Logs disabled" || echo "- Audit Logs enabled"
    echo
    echo "Scope: organizations/${ORG_NUM}"
    echo

    if ((${#missing[@]} == 0)); then
        echo -e "${GREEN}Permissions OK${NC} — all required GCP organization permissions are granted."
        printf '  - %s\n' "${req_perms[@]}"
        echo
        echo "You can onboard this GCP Organization to Cortex Cloud."
        return 0
    else
        echo -e "${RED}Missing organization permissions:${NC}"
        printf '  - %s\n' "${missing[@]}"
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

# # Normalizinf in lowercase
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
