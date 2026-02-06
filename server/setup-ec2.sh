#!/bin/bash
# setup-ec2.sh - Runs on the EC2 instance to set up the Schwab API server
#
# This script is uploaded and executed by deploy.sh.
# Expects EC2_PUBLIC_IP environment variable to be set.

set -euo pipefail

if [ -z "${EC2_PUBLIC_IP:-}" ]; then
    echo "ERROR: EC2_PUBLIC_IP environment variable is not set"
    exit 1
fi

echo "=== Setting up Schwab API Server on EC2 ==="
echo "Public IP: $EC2_PUBLIC_IP"

# Step 1: Install Node.js 18
echo ""
echo "--- Installing Node.js 18 ---"
if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    echo "Node.js already installed: $(node --version)"
fi

# Step 2: Install pm2 globally
echo ""
echo "--- Installing pm2 ---"
if ! command -v pm2 >/dev/null 2>&1; then
    sudo npm install -g pm2
else
    echo "pm2 already installed"
fi

# Step 3: Extract server code
echo ""
echo "--- Extracting server code ---"
APP_DIR="$HOME/schwab-server"
mkdir -p "$APP_DIR"

tar -xzf /tmp/schwab-server.tar.gz -C "$APP_DIR" --strip-components=1
rm -f /tmp/schwab-server.tar.gz

# Step 4: Install npm dependencies
echo ""
echo "--- Installing npm dependencies ---"
cd "$APP_DIR"
npm install

# Step 5: Configure .env with EC2 public IP
echo ""
echo "--- Configuring .env ---"
if [ -f "$APP_DIR/.env" ]; then
    # Update SCHWAB_REDIRECT_URI to use EC2 public IP
    sed -i "s|SCHWAB_REDIRECT_URI=.*|SCHWAB_REDIRECT_URI=https://$EC2_PUBLIC_IP:5000/callback|" "$APP_DIR/.env"

    # Add EC2_PUBLIC_IP to .env if not already present
    if grep -q "EC2_PUBLIC_IP" "$APP_DIR/.env"; then
        sed -i "s|EC2_PUBLIC_IP=.*|EC2_PUBLIC_IP=$EC2_PUBLIC_IP|" "$APP_DIR/.env"
    else
        echo "" >> "$APP_DIR/.env"
        echo "# EC2 deployment - public IP for cert SAN and binding" >> "$APP_DIR/.env"
        echo "EC2_PUBLIC_IP=$EC2_PUBLIC_IP" >> "$APP_DIR/.env"
    fi
else
    echo "WARNING: .env file not found. Server will start without credentials."
fi

# Remove any existing certs so they get regenerated with the EC2 IP in SAN
rm -f "$APP_DIR/cert.pem" "$APP_DIR/key.pem"

echo ""
echo "--- .env contents (credentials redacted) ---"
grep -v "SECRET" "$APP_DIR/.env" | grep -v "^$"

# Step 6: Stop any existing pm2 process
echo ""
echo "--- Starting server with pm2 ---"
pm2 delete schwab-api-server 2>/dev/null || true

# Step 7: Start the server
cd "$APP_DIR"
pm2 start server.js --name schwab-api-server

# Configure pm2 to start on boot
pm2 save
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u ubuntu --hp /home/ubuntu 2>/dev/null || true

# Step 8: Wait and verify
echo ""
echo "--- Verifying server is running ---"
sleep 3

if curl -sk "https://localhost:5000/health" | grep -q '"status":"ok"'; then
    echo "Server is running and healthy!"
else
    echo "WARNING: Health check failed. Checking pm2 logs..."
    pm2 logs schwab-api-server --lines 20 --nostream
fi

echo ""
echo "=== EC2 Setup Complete ==="
echo "Server URL:   https://$EC2_PUBLIC_IP:5000"
echo "Callback URL: https://$EC2_PUBLIC_IP:5000/callback"
echo "PM2 status:   pm2 status"
echo "PM2 logs:     pm2 logs"
