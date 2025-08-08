# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Libvirt-friendly Ubuntu 22.04 (Jammy) base box
  # Requires: vagrant plugin install vagrant-libvirt
  config.vm.box = "generic/ubuntu2204"

  # Use rsync to avoid NFS and virtiofs requirements on libvirt
  config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__args: ["--verbose", "--archive", "--delete", "-z"], rsync__exclude: ["/target", ".git/", ".vagrant/"]

  # Network (optional): forward CrowdSec LAPI if desired (libvirt supports)
  # config.vm.network "forwarded_port", guest: 8080, host: 8080

  # Libvirt provider settings
  config.vm.provider :libvirt do |lv|
    lv.memory = 2048
    lv.cpus   = 2
    # Uncomment to use a specific network or bridge
    # lv.management_network_name = 'vagrant-libvirt'
    # lv.driver = 'kvm'
  end

  config.vm.provision "shell", inline: <<-'SHELL'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[+] Apt update and base packages"
sudo apt-get update -y
sudo apt-get install -y curl gnupg2 build-essential pkg-config iptables ipset nftables jq unzip ca-certificates libssl-dev

echo "[+] Install CrowdSec"
curl -s https://install.crowdsec.net | sudo sh || true
sudo apt-get install -y crowdsec

echo "[+] Ensure CrowdSec LAPI is running"
sudo systemctl enable --now crowdsec || true

echo "[+] Create bouncer API key"
KEY=$(sudo cscli bouncers add cs-rs-bouncer -o raw 2>/dev/null || true)
if [ -z "$KEY" ]; then
  # try to fetch existing bouncer key if it exists
  KEY=$(sudo cscli bouncers list -o json | jq -r '.[] | select(.name=="cs-rs-bouncer") | .api_key' || true)
fi
if [ -z "$KEY" ]; then
  echo "[-] Failed to obtain bouncer key automatically. You can set api_key manually in /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml"
  KEY="YOUR_API_KEY"
fi

echo "[+] Write bouncer config from template"
sudo mkdir -p /etc/crowdsec/bouncers
if [ -f /vagrant/config/cs-firewall-bouncer.yaml.example ]; then
  sudo cp /vagrant/config/cs-firewall-bouncer.yaml.example /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml
else
  # fallback minimal file
  echo "mode: iptables" | sudo tee /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml >/dev/null
  echo "api_url: http://127.0.0.1:8080" | sudo tee -a /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml >/dev/null
  echo "api_key: ${KEY}" | sudo tee -a /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml >/dev/null
  echo "update_frequency: 10s" | sudo tee -a /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml >/dev/null
fi
# Replace placeholders
sudo sed -i "s#\${API_URL}#http://127.0.0.1:8080#g" /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml
sudo sed -i "s#\${API_KEY}#${KEY}#g" /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml

echo "[+] Install Rust toolchain (rustup)"
if ! command -v cargo >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable
  source $HOME/.cargo/env
fi

echo "[+] Build cs-firewall-bouncer (release)"
cd /vagrant
if [ ! -f Cargo.toml ]; then
  echo "[-] Cargo.toml not found in /vagrant. Ensure synced folder is mounted."
  mount | grep /vagrant || true
  ls -la /vagrant || true
  exit 1
fi
cargo build --release --features backends-iptables || exit 1
sudo install -m 0755 target/release/cs-firewall-bouncer /usr/local/bin/cs-firewall-bouncer

echo "[+] Install systemd service"
sudo mkdir -p /etc/systemd/system
if [ -f /vagrant/config/systemd/cs-firewall-bouncer.service ]; then
  sudo cp /vagrant/config/systemd/cs-firewall-bouncer.service /etc/systemd/system/
else
  sudo tee /etc/systemd/system/cs-firewall-bouncer.service >/dev/null <<'UNIT'
[Unit]
Description=CrowdSec Firewall Bouncer (Rust)
After=network.target crowdsec.service
Wants=crowdsec.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/cs-firewall-bouncer -c /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml -v
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNIT
fi

echo "[+] Enable and start service"
sudo systemctl daemon-reload
sudo systemctl enable --now cs-firewall-bouncer

echo "[+] Done. Check status with: systemctl status cs-firewall-bouncer | cat"
SHELL
end


