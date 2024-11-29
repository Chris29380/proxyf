#!/bin/bash
COLOR1='\033[0;31m'
COLOR2='\033[1;34m'
COLOR3='\033[1;33m'
NC='\033[0m' # No Color

# -----------------------------------------------------------
# check sudo permissions
# -----------------------------------------------------------
if [ "$(id -u)" != "0" ]; then
    echo -e "${COLOR1} This script must be run as root ${NC}" 1>&2
    exit 1
fi

upgrade_machine(){
    apt update 
    apt upgrade -y
}

upgrade_machine

install_nginx(){
    echo
    echo -e "${COLOR2} UPDATE Packages ... ${NC}"
    apt-get update
    echo -e "${COLOR2} Nginx Installation ... ${NC}"
    echo
    apt-get install nginx-extras -y
    apt-get install libnginx-mod-stream -y
    echo
    echo -e "${COLOR2} Nginx Installation done ! ... ${NC}"
    echo
}

install_nginx

install_ssl(){
    echo
    echo -e "${COLOR2} Certbot Installation ... ${NC}"
    apt install -y certbot python3-certbot-nginx
}

install_ssl

install_php(){
    echo
    echo -e "${COLOR2} UPDATE Packages ... ${NC}"
    apt-get update
    echo -e "${COLOR2} PHP 8.2 Installation ... ${NC}"
    echo
    apt-get install php8.2 php8.2-cli php8.2-{bz2,curl,mbstring,intl,fpm} -y
    apt purge apache2 apache2-utils
    echo
    echo -e "${COLOR2} PHP 8.2 Installation done ! ... ${NC}"
    echo
}

install_php

install_certbot(){
    echo
    certbot --nginx -d proxyf.cdtfivem.com
    echo -e "${COLOR2} Copy Config files ... ${NC}"
    cp ./nginx/default /etc/nginx/sites-enabled/default
    cp ./nginx/nginx.conf /etc/nginx/nginx.conf
}

install_certbot