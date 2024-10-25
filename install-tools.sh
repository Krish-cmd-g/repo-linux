#!/bin/bash
sudo yum update -y
sudo yum install -y git vim curl wget htop gcc-c++ make

sudo yum install -y bind bind-utils

sudo yum install -y httpd
sudo systemctl enable httpd
sudo systemctl start httpd


sudo yum install -y mariadb-server mariadb
sudo systemctl enable mariadb
sudo systemctl start mariadb
sudo mysql_secure_installation

