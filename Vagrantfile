# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"

  config.vm.provider "vmware_desktop" do |v|
    v.memory = 2048
    v.cpus = 2
  end

  # Backend VM: runs echo servers for testing
  config.vm.define "backend" do |backend|
    backend.vm.hostname = "backend"
    backend.vm.network "private_network", type: "dhcp"

    backend.vm.provision "shell", inline: <<-SHELL
      apt-get update -qq
      apt-get install -y -qq socat > /dev/null

      # TCP echo servers
      cat > /etc/systemd/system/echo-tcp@.service <<'EOF'
[Unit]
Description=TCP echo server on port %i
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:%i,fork,reuseaddr EXEC:/bin/cat
Restart=always

[Install]
WantedBy=multi-user.target
EOF

      # UDP echo servers
      cat > /etc/systemd/system/echo-udp@.service <<'EOF'
[Unit]
Description=UDP echo server on port %i
After=network.target

[Service]
ExecStart=/usr/bin/socat UDP-RECVFROM:%i,fork EXEC:/bin/cat
Restart=always

[Install]
WantedBy=multi-user.target
EOF

      systemctl daemon-reload
      systemctl enable --now echo-tcp@8080 echo-tcp@9090
      systemctl enable --now echo-udp@5353 echo-udp@6363
    SHELL
  end

  # Proxy VM: builds vtether and runs XDP forwarding
  config.vm.define "proxy" do |proxy|
    proxy.vm.hostname = "proxy"
    proxy.vm.network "private_network", type: "dhcp"

    proxy.vm.provision "shell", inline: <<-SHELL
      apt-get update -qq
      apt-get install -y -qq build-essential pkg-config libssl-dev > /dev/null

      # Install Rust nightly with bpf-linker
      if ! command -v rustup &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
          sh -s -- -y --default-toolchain nightly
      fi
      source /root/.cargo/env
      rustup component add rust-src
      cargo install bpf-linker

      # Build vtether
      cd /vagrant
      cargo build --release
    SHELL
  end
end
