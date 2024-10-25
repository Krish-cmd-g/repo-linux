#!/bin/bash


sudo yum update -y

# Install BIND
sudo yum install -y bind bind-utils

# Configuring  named.conf
cat <<EOL | sudo tee /etc/named.conf
options {
    listen-on port 53 { any; };
    directory       "/var/named";
    dump-file       "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";
    secroots-file   "/var/named/data/named.secroots";
    recursing-file  "/var/named/data/named.recursing";
    allow-query     { any; };
};

zone "." IN {
    type hint;
    file "named.ca";
};

zone "example.com" IN {
    type master;
    file "example.com.db";
    allow-update { none; };
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
EOL

# Configuring  example.com.db
cat <<EOL | sudo tee /var/named/example.com.db
\$TTL 86400
@   IN  SOA ns1.example.com. root.example.com. (
        2021100401  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400 )     ; Minimum TTL
@   IN  NS  ns1.example.com.
ns1 IN  A   192.168.1.10
@   IN  A   192.168.1.10
EOL

#  permissions
sudo chown named:named /var/named/example.com.db
sudo chmod 640 /var/named/example.com.db

# Start and enable BIND
sudo systemctl restart named
sudo systemctl enable named

# firewall
sudo firewall-cmd --permanent --add-port=53/udp
sudo firewall-cmd --permanent --add-port=53/tcp
sudo firewall-cmd --reload

echo "DNS server setup complete."

