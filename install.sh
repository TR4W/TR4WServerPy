#\!/bin/bash
# TR4WSERVER Installation Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing TR4WSERVER as a systemd service..."

# Update service file with correct path
sed -i "s|/home/pi/tr4wserverpy|$SCRIPT_DIR|g" "$SCRIPT_DIR/tr4wserver.service"

# Copy service file
sudo cp "$SCRIPT_DIR/tr4wserver.service" /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable tr4wserver

# Start the service
sudo systemctl start tr4wserver

echo ""
echo "Installation complete\!"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status tr4wserver   - Check status"
echo "  sudo systemctl stop tr4wserver     - Stop server"
echo "  sudo systemctl restart tr4wserver  - Restart server"
echo "  sudo journalctl -u tr4wserver -f   - View logs"
