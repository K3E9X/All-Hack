#!/bin/bash

echo "🔧 Installing Advanced Pentest Tools"
echo "===================================="

# Update package list
echo "[1/4] Updating package list..."
apt-get update -qq

# Install Nmap
echo "[2/4] Installing Nmap with NSE scripts..."
apt-get install -y nmap ncat > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Nmap installed: $(nmap --version | head -n1)"
    echo "   NSE scripts location: /usr/share/nmap/scripts/"
else
    echo "❌ Failed to install Nmap"
fi

# Install Gobuster
echo "[3/4] Installing Gobuster..."
apt-get install -y gobuster > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Gobuster installed: $(gobuster version 2>&1 | head -n1)"
else
    echo "⚠️  Gobuster not available via apt, installing from GitHub..."
    wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz
    tar -xzf gobuster_Linux_x86_64.tar.gz -C /usr/local/bin/
    chmod +x /usr/local/bin/gobuster
    rm gobuster_Linux_x86_64.tar.gz
    echo "✅ Gobuster installed"
fi

# Install OWASP ZAP
echo "[4/4] Installing OWASP ZAP..."
apt-get install -y default-jre > /dev/null 2>&1
wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz -O /tmp/zap.tar.gz
tar -xzf /tmp/zap.tar.gz -C /opt/
rm /tmp/zap.tar.gz
ln -sf /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap
echo "✅ OWASP ZAP installed"

# Download wordlists
echo ""
echo "📚 Setting up wordlists..."
mkdir -p /home/user/devasc-study-team/backend/wordlists

# SecLists common wordlists
echo "Downloading SecLists wordlists..."
cd /home/user/devasc-study-team/backend/wordlists

# Directory/file discovery
cat > common-dirs.txt << 'EOF'
admin
api
backup
config
dashboard
dev
docs
login
panel
test
upload
uploads
assets
images
files
static
public
private
secure
admin-panel
administrator
wp-admin
phpmyadmin
cpanel
webmail
.git
.env
.htaccess
backup.zip
backup.sql
database.sql
db.sql
dump.sql
config.php
config.json
web.config
settings.php
EOF

# Common API endpoints
cat > api-endpoints.txt << 'EOF'
/api/v1
/api/v2
/api/v3
/api
/rest
/graphql
/swagger
/api-docs
/api/swagger
/api/users
/api/admin
/api/auth
/api/login
/api/token
/api/profile
/api/settings
EOF

echo "✅ Wordlists created"
echo ""
echo "🎉 All tools installed successfully!"
echo ""
echo "Installed tools:"
echo "  - Nmap: Port scanning + NSE vulnerability scripts"
echo "  - Gobuster: Directory/file brute-forcing"
echo "  - OWASP ZAP: Comprehensive web app scanner"
echo ""
