#!/bin/bash
# deploy.sh - Provision an EC2 instance and deploy the Schwab API server
#
# Prerequisites:
#   1. AWS CLI installed and configured (aws configure)
#   2. Schwab API credentials in server/.env
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh

set -euo pipefail

# Configuration
KEY_NAME="schwab-api-server-key"
SECURITY_GROUP_NAME="schwab-api-server-sg"
INSTANCE_TYPE="t2.micro"
PROJECT_NAME="schwab-api-server"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check prerequisites
command -v aws >/dev/null 2>&1 || error "AWS CLI not installed. Run: curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip' && unzip awscliv2.zip && sudo ./aws/install"

aws sts get-caller-identity >/dev/null 2>&1 || error "AWS CLI not configured. Run: aws configure"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    error ".env file not found at $ENV_FILE. Copy .env.example and add your Schwab credentials."
fi

# Get the default region
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
log "Using AWS region: $REGION"

# Get the latest Ubuntu 22.04 AMI for the region
log "Finding latest Ubuntu 22.04 AMI..."
AMI_ID=$(aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
              "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text \
    --region "$REGION")

if [ -z "$AMI_ID" ] || [ "$AMI_ID" = "None" ]; then
    error "Could not find Ubuntu 22.04 AMI in region $REGION"
fi
log "Using AMI: $AMI_ID"

# Step 1: Create key pair (if it doesn't exist)
# Store key in ~/.ssh/ because chmod doesn't work on /mnt/c/ (WSL + NTFS)
KEY_FILE="$HOME/.ssh/${KEY_NAME}.pem"
mkdir -p "$HOME/.ssh"

if aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" >/dev/null 2>&1; then
    warn "Key pair '$KEY_NAME' already exists"
    if [ ! -f "$KEY_FILE" ]; then
        error "Key pair exists in AWS but local .pem file is missing at $KEY_FILE. Delete the key pair in AWS console and re-run, or place the .pem file there."
    fi
else
    log "Creating EC2 key pair: $KEY_NAME"
    aws ec2 create-key-pair \
        --key-name "$KEY_NAME" \
        --query 'KeyMaterial' \
        --output text \
        --region "$REGION" > "$KEY_FILE"
    chmod 400 "$KEY_FILE"
    log "Key pair saved to: $KEY_FILE"
fi

# Step 2: Create security group (if it doesn't exist)
VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' \
    --output text \
    --region "$REGION")

if [ -z "$VPC_ID" ] || [ "$VPC_ID" = "None" ]; then
    error "No default VPC found in region $REGION. Create one in the AWS console."
fi

SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$SECURITY_GROUP_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
    log "Creating security group: $SECURITY_GROUP_NAME"
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$SECURITY_GROUP_NAME" \
        --description "Security group for Schwab API server - allows SSH and HTTPS on port 5000" \
        --vpc-id "$VPC_ID" \
        --query 'GroupId' \
        --output text \
        --region "$REGION")

    # Allow SSH (port 22)
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"

    # Allow HTTPS server (port 5000)
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 5000 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"

    log "Security group created: $SG_ID (ports 22, 5000 open)"
else
    warn "Security group '$SECURITY_GROUP_NAME' already exists: $SG_ID"
fi

# Step 3: Check for existing instance
EXISTING_INSTANCE=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$PROJECT_NAME" \
              "Name=instance-state-name,Values=running,pending,stopped" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "None")

if [ "$EXISTING_INSTANCE" != "None" ] && [ -n "$EXISTING_INSTANCE" ]; then
    warn "Existing instance found: $EXISTING_INSTANCE"
    read -p "Terminate existing instance and create a new one? (y/N): " CONFIRM
    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
        log "Terminating existing instance..."
        aws ec2 terminate-instances --instance-ids "$EXISTING_INSTANCE" --region "$REGION" >/dev/null
        aws ec2 wait instance-terminated --instance-ids "$EXISTING_INSTANCE" --region "$REGION"
        log "Instance terminated"
    else
        # Get existing instance IP and reuse
        PUBLIC_IP=$(aws ec2 describe-instances \
            --instance-ids "$EXISTING_INSTANCE" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' \
            --output text \
            --region "$REGION")
        if [ "$PUBLIC_IP" != "None" ] && [ -n "$PUBLIC_IP" ]; then
            log "Using existing instance at $PUBLIC_IP"
            log "Uploading code to existing instance..."
            # Skip to upload step
            INSTANCE_ID="$EXISTING_INSTANCE"
            SKIP_LAUNCH=true
        else
            error "Existing instance has no public IP. Terminate it and re-run."
        fi
    fi
fi

# Step 4: Launch EC2 instance
if [ "${SKIP_LAUNCH:-false}" = "false" ]; then
    log "Launching EC2 instance ($INSTANCE_TYPE)..."
    INSTANCE_ID=$(aws ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_ID" \
        --associate-public-ip-address \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$PROJECT_NAME}]" \
        --query 'Instances[0].InstanceId' \
        --output text \
        --region "$REGION")

    log "Instance launched: $INSTANCE_ID"
    log "Waiting for instance to be running..."
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

    # Get public IP
    PUBLIC_IP=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text \
        --region "$REGION")

    log "Instance is running at: $PUBLIC_IP"

    # Wait for SSH to be ready
    log "Waiting for SSH to be ready (this may take 30-60 seconds)..."
    for i in $(seq 1 30); do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
            -i "$KEY_FILE" "ubuntu@$PUBLIC_IP" "echo ready" 2>/dev/null; then
            break
        fi
        sleep 5
        if [ "$i" -eq 30 ]; then
            error "SSH connection timed out. Instance may still be initializing. Try running the upload step manually."
        fi
    done
    log "SSH is ready!"
fi

# Step 5: Upload server code to EC2
log "Uploading server code to EC2..."

# Create a tarball of the server directory (excluding node_modules, certs, tokens)
TARBALL="/tmp/schwab-server.tar.gz"
tar -czf "$TARBALL" \
    -C "$SCRIPT_DIR/.." \
    --exclude='server/node_modules' \
    --exclude='server/cert.pem' \
    --exclude='server/key.pem' \
    --exclude='server/tokens.json' \
    --exclude='server/*.pem' \
    --exclude='server/deploy.sh' \
    --exclude='server/setup-ec2.sh' \
    server/

scp -o StrictHostKeyChecking=no -i "$KEY_FILE" \
    "$TARBALL" "ubuntu@$PUBLIC_IP:/tmp/schwab-server.tar.gz"

scp -o StrictHostKeyChecking=no -i "$KEY_FILE" \
    "$SCRIPT_DIR/setup-ec2.sh" "ubuntu@$PUBLIC_IP:/tmp/setup-ec2.sh"

rm -f "$TARBALL"
log "Code uploaded"

# Step 6: Run setup script on EC2
log "Running setup script on EC2 (installing Node.js, dependencies, starting server)..."
ssh -o StrictHostKeyChecking=no -i "$KEY_FILE" "ubuntu@$PUBLIC_IP" \
    "chmod +x /tmp/setup-ec2.sh && EC2_PUBLIC_IP=$PUBLIC_IP /tmp/setup-ec2.sh"

# Step 7: Save deployment info
DEPLOY_INFO="$SCRIPT_DIR/deploy-info.txt"
cat > "$DEPLOY_INFO" <<EOF
Schwab API Server - EC2 Deployment Info
========================================
Date:          $(date)
Instance ID:   $INSTANCE_ID
Public IP:     $PUBLIC_IP
Region:        $REGION
Key File:      $KEY_FILE
Security Group: $SG_ID

Server URL:    https://$PUBLIC_IP:5000
Callback URL:  https://$PUBLIC_IP:5000/callback
SSH Command:   ssh -i $KEY_FILE ubuntu@$PUBLIC_IP
EOF

log "Deployment info saved to: $DEPLOY_INFO"

echo ""
echo "========================================"
echo -e "${GREEN}  DEPLOYMENT COMPLETE${NC}"
echo "========================================"
echo ""
echo "  Server URL:    https://$PUBLIC_IP:5000"
echo "  Callback URL:  https://$PUBLIC_IP:5000/callback"
echo ""
echo "  Next steps:"
echo "  1. Update Schwab developer portal callback URL to:"
echo "     https://$PUBLIC_IP:5000/callback"
echo ""
echo "  2. Visit https://$PUBLIC_IP:5000 in your browser"
echo "     and accept the self-signed certificate"
echo ""
echo "  3. Update Simple_FrontEnd_React.html:"
echo "     Change API_BASE to 'https://$PUBLIC_IP:5000'"
echo ""
echo "  4. Open Simple_FrontEnd_React.html and login"
echo ""
echo "  SSH access:  ssh -i $KEY_FILE ubuntu@$PUBLIC_IP"
echo "  View logs:   ssh -i $KEY_FILE ubuntu@$PUBLIC_IP 'pm2 logs'"
echo "========================================"
