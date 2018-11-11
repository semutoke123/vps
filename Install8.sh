#!/bin/bash
# go to root
cd
echo -e "\e[32;32;32m " 
echo " Welcome To Script Automatic Install  Army Phreakers Nusantara "
echo " Script Modified By Reza Adrian | Whatsapp: 081214422324 "
echo "========================================"
echo "CLICK 'I' SETUP VPS Non-Local"
echo "CLICK 'L' SETUP VPS Local" 
echo "========================================"
read -p "Location : " -e loc
apt-get update

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# data pemilik server
read -p "Nama pemilik server: " namap
echo "Proses instalasi script dimulai....."

MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

#detail nama perusahaan
country=ID
state=Jakarta
locality=Depok
organization=kumpul4semut
organizationalunit=IT
commonname=Premiumssh.xyz
email=semutkece6@gmail.com

# go to root
cd
echo "=============================="
echo "        Setup Awal        "
echo "=============================="
echo -e "\e[32;32;32m"    
# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
#sed -i 's/net.ipv6.conf.all.disable_ipv6 = 0/net.ipv6.conf.all.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.default.disable_ipv6 = 0/net.ipv6.conf.default.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.lo.disable_ipv6 = 0/net.ipv6.conf.lo.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.eth0.disable_ipv6 = 0/net.ipv6.conf.eth0.disable_ipv6 = 1/g' /etc/sysctl.conf
#sysctl -p
echo -e "\e[32;32;32m " 
echo "=============================="
echo "     INSTALL CURL     "
echo "=============================="
# install wget and curl
apt-get update;apt-get -y install wget curl;
apt-get install gem
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart
# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y --purge remove dropbear*;
#apt-get -y autoremove;
echo -e "\e[32;32;32m " 
echo "=============================="
echo "       REPOSITORI "
echo "=============================="
# set repo
ver=`cat /etc/debian_version`
if [ $ver = '8.0' ]
then
debver='8'
elif [ $ver = '8.1' ]
then
debver='8'
elif [ $ver = '8.2' ]
then
debver='8'
elif [ $ver = '8.3' ]
then
debver='8'
elif [ $ver = '8.4' ]
then
debver='8'
elif [ $ver = '8.5' ]
then
debver='8'
elif [ $ver = '8.6' ]
then
debver='8'
elif [ $ver = '8.7' ]
then
debver='8'
elif [ $ver = '8.8' ]
then
debver='8'
elif [ $ver = '8.9' ]
then
debver='8'
else
debver='Null'
fi
if [ $debver = '8' ]; then
	if [[ "$loc" = "I" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "L" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
    apt-get update
	elif [[ "$loc" = "i" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "l" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	fi
else
	cd
fi

gpg --keyserver pgpkeys.mit.edu --recv-key  9D6D8F6BC857C906      
gpg -a --export 9D6D8F6BC857C906 | sudo apt-key add -
gpg --keyserver pgpkeys.mit.edu --recv-key  7638D0442B90D010      
gpg -a --export 7638D0442B90D010 | sudo apt-key add -

# update
apt-get update;apt-get -y upgrade;

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon 
apt-get -y install iftop 
apt-get -y install htop 
apt-get -y install nmap 
apt-get -y install axel 
apt-get -y install nano 
apt-get -y install iptables 
apt-get -y install traceroute 
apt-get -y install sysv-rc-conf 
apt-get -y install dnsutils 
apt-get -y install bc 
apt-get -y install nethogs
apt-get -y install openvpn 
apt-get -y install vnstat 
apt-get -y install less 
apt-get -y install screen 
apt-get -y install psmisc 
apt-get -y install apt-file 
apt-get -y install whois 
apt-get -y install ptunnel 
apt-get -y install ngrep 
apt-get -y install mtr 
apt-get -y install git 
apt-get -y install zsh 
apt-get -y install mrtg 
apt-get -y install snmp 
apt-get -y install snmpd 
apt-get -y install snmp-mibs-downloader 
apt-get -y install unzip 
apt-get -y install unrar 
apt-get -y install rsyslog 
apt-get -y install debsums 
apt-get -y install rkhunter
apt-get -y install build-essential
apt-get -y --force-yes -f install libxml-parser-perl
echo -e "\e[32;32;32m"  
echo "=============================="
echo "  UPDATE ALL SERVICE        "
echo "=============================="

# disable exim
service exim4 stop
sysv-rc-conf exim4 off
# update apt-file
apt-file update
# setting vnstat
vnstat -u -i $ether
service vnstat restart

    NORMAL=`echo "\033[m"`
    MENU=`echo "\033[36m"` #Blue
    NUMBER=`echo "\033[33m"` #yellow
    FGRED=`echo "\033[41m"`
    RED_TEXT=`echo "\033[31m"`
	LGREEN=`echo "\033[0m\033[1;32m"`
    ENTER_LINE=`echo "\033[33m"`
	LRED=`echo "\033[0m\033[1;31m"`
	BLUE=`echo "\033[0m\033[1;36m"`


# go to root
cd

# install screenfetch
cd
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/screenfetch.sh
mv screenfetch-dev /usr/bin/screenfetch-dev
chmod +x /usr/bin/screenfetch-dev

# install gambar boxes
apt-get install boxes

# text warna pelangi
apt-get install ruby
gem install lolcat 

# tampilan unik awal login
#cd
#rm -rf /root/.bashrc
#wget -O /root/.bashrc "https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/welcome.sh"

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -q -O /etc/nginx/nginx.conf https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/nginx.conf
mkdir -p /home/fns/public_html
echo "<pre>Default Webpage</pre><br/><pre>Auto Installer Script Premium - ForNesia Community</pre>" > /home/fns/public_html/index.html
echo "<?php phpinfo(); ?>" > /home/fns/public_html/info.php
wget -q -O /etc/nginx/conf.d/vps.conf https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/vps.conf
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

# install openvpn
wget -O /etc/openvpn/openvpn.tar "https://github.com/Mr-Kenyut/VPS/blob/master/openvpn-debian.rar?raw=true"
cd /etc/openvpn/
tar xf openvpn.t
wget -O /etc/openvpn/1194.conf "https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/1194.conf"
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables.conf
wget -O /etc/network/if-up.d/iptables "https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/iptables.conf"
chmod +x /etc/network/if-up.d/iptables
service openvpn restart

# konfigurasi openvpn
cd /etc/openvpn/
wget -O /etc/openvpn/client.ovpn "https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/client-1194.conf"
sed -i $MYIP2 /etc/openvpn/client.ovpn;
cp client.ovpn /home/vps/public_html/

# setting port ssh
cd
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
service ssh restart

# configure ssh
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=444/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 80 -p 110"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# upgrade dropbear 2017
apt-get install zlib1g-dev
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
bzip2 -cd dropbear-2017.75.tar.bz2 | tar xvf -
cd dropbear-2017.75
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://github.com/ForNesiaFreak/FNS/raw/master/sett/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
wget -O /usr/bin/badvpn-udpgw "https://github.com/ForNesiaFreak/FNS/raw/master/sett/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200

# Install VNSTAT
apt-get install vnstat -y
cd /home/vps/public_html/
wget $source/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
if [[ `ifconfig -a | grep "venet0"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "venet0:0"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "venet0:0-00"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "venet0-00"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "eth0"` ]]
then
cekvirt='KVM'
elif [[ `ifconfig -a | grep "eth0:0"` ]]
then
cekvirt='KVM'
elif [[ `ifconfig -a | grep "eth0:0-00"` ]]
then
cekvirt='KVM'
elif [[ `ifconfig -a | grep "eth0-00"` ]]
then
cekvirt='KVM'
fi
if [ $cekvirt = 'KVM' ]; then
	sed -i 's/eth0/eth0/g' config.php
	sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
	sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
	sed -i 's/Internal/Internet/g' config.php
	sed -i "s/\$locale = 'en_US.UTF-8';/\$locale = 'en_US.UTF+8';/g" config.php
	cd
elif [ $cekvirt = 'OpenVZ' ]; then
	sed -i 's/eth0/venet0/g' config.php
	sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array('venet0');/g" config.php
	sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
	sed -i 's/Internal/Internet/g' config.php
	sed -i '/SixXS IPv6/d' config.php
	cd
else
	cd
fi
echo -e "\e[32;32;32m"
echo "=============================="
echo "        INSTALL BADVPN       "
echo "=============================="

# nstall fail2ban
apt-get -y install fail2ban;service fail2ban restart

# Instal (D)DoS Deflate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# install squid3
apt-get -y install squid3
wget https://raw.githubusercontent.com/hidden-refuge/spi/master/spi && bash spi -jessie && rm spi
service squid3 restart

# install webmin
cd
apt-get -y install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
wget -O webmin-current.deb "http://www.webmin.com/download/deb/webmin-current.deb"
dpkg -i --force-all webmin-current.deb;
apt-get -y -f install;
rm /root/webmin-current.deb
service webmin restart
service vnstat restart

# install dos2unix
apt-get install dos2unix

wget -q https://github.com/ForNesiaFreak/FNS/raw/master/go/fornesia87.tgz
tar xvfz fornesia87.tgz
cd fornesia87
make

# install New pptp vpn 
wget -q https://raw.githubusercontent.com/akumasih112/code/master/null/addpptp.sh

# install stunnel
apt-get -y install stunnel4
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
pid = /stunnel.pid
client = no	
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 443
connect = 127.0.0.1:109
connect = 127.0.0.1:110
[ssh]
accept = 21
connect = 127.0.0.1:143
;[squid]
;connect = 127.0.0.1:8080
END

#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

#konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart


#ADD MENU + Compiler

wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/menu.sh
dos2unix /root/fornesia87/menu.sh


# download script lain + Compile
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-login.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-renew.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-expired.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-list.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/add-del.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/useradd.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-pass.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/mrtg.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/vnstat.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/dropmon.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-ban.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-unban.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/expiry-change.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/user-limit.sh
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/del-user-expire.sh


./shc -v -r -T -f menu.sh
./shc -v -r -T -f addpptp.sh
./shc -v -r -T -f bench-network.sh
./shc -v -r -T -f user-login.sh
./shc -v -r -T -f user-renew.sh
./shc -v -r -T -f user-expired.sh
./shc -v -r -T -f user-list.sh
./shc -v -r -T -f add-del.sh
./shc -v -r -T -f useradd.sh
./shc -v -r -T -f user-pass.sh
./shc -v -r -T -f mrtg.sh
./shc -v -r -T -f vnstat.sh
./shc -v -r -T -f dropmon.sh
./shc -v -r -T -f user-ban.sh
./shc -v -r -T -f user-unban.sh
./shc -v -r -T -f expiry-change.sh
./shc -v -r -T -f user-limit.sh
./shc -v -r -T -f del-user-expire.sh

cp /root/fornesia87/menu.sh.x /usr/bin/menu
cp /root/fornesia87/addpptp.sh.x /usr/bin/add-pptp
cp /root/fornesia87/user-login.sh.x /usr/bin/user-login
cp /root/fornesia87/user-renew.sh.x /usr/bin/user-renew
cp /root/fornesia87/dropmon.sh.x /usr/bin/dropmon
cp /root/fornesia87/user-expired.sh.x /usr/bin/user-expired
cp /root/fornesia87/user-list.sh.x /usr/bin/user-list
cp /root/fornesia87/add-del.sh.x /usr/bin/add-del
cp /root/fornesia87/useradd.sh.x /usr/bin/user-add
cp /root/fornesia87/user-pass.sh.x /usr/bin/user-pass
cp /root/fornesia87/mrtg.sh.x /usr/bin/mrtg
cp /root/fornesia87/vnstat.sh.x /usr/bin/vnstat
cp /root/fornesia87/user-ban.sh.x /usr/bin/user-ban
cp /root/fornesia87/user-unban.sh.x /usr/bin/user-unban
cp /root/fornesia87/expiry-change.sh.x /usr/bin/expiry-change
cp /root/fornesia87/user-limit.sh.x /usr/bin/user-limit
cp /root/fornesia87/del-user-expire.sh.x /usr/bin/del-user-expired

# Download Lain
cd
wget -q -O /usr/bin/welcomeadmin https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/welcome.sh
wget -q -O /usr/bin/benchmark https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/Bench.sh
wget -q -O /usr/bin/speedtest https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/speedtest.py
wget -q -O /usr/bin/ps-mem https://raw.githubusercontent.com/pixelb/ps_mem/master/ps_mem.py
wget -q -O /etc/issue.net https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/Banner.txt

# Admin Welcome
chmod +x /usr/bin/welcomeadmin
echo "clear" >> .profile
echo "welcomeadmin" >> .profile

# Banner login
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
service sshd restart &&  service dropbear restart

chmod +x /usr/bin/speedtest
chmod +x /usr/bin/add-pptp
chmod +x /usr/bin/benchmark
chmod +x /usr/bin/ps-mem
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/user-expired
chmod +x /usr/bin/user-list
chmod +x /usr/bin/add-del
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/mrtg
chmod +x /usr/bin/vnstat
chmod +x /usr/bin/user-expired
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-ban
chmod +x /usr/bin/user-unban
chmod +x /usr/bin/expiry-change
chmod +x /usr/bin/user-limit
chmod +x /usr/bin/del-user-expired


# blokir Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# blokir sony playstation
iptables -A FORWARD -m string --algo bm --string "account.sonyentertainmentnetwork.com" -j DROP
iptables -A FORWARD -m string --algo bm --string "auth.np.ac.playstation.net" -j DROP
iptables -A FORWARD -m string --algo bm --string "auth.api.sonyentertainmentnetwork.com" -j DROP
iptables -A FORWARD -m string --algo bm --string "auth.api.np.ac.playstation.net" -j DROP

# finishing
chown -R www-data:www-data /home/fns/public_html
service cron restart
service openvpn restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo -e "${LRED}Autoscript Includes:${NORMAL}" | tee log-install.txt
echo "===========================================" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo -e "Tampilan Menu VPS Premium " | tee -a log-install.txt
	echo -e "----------- Selamat Datang di Server - IP: $IP -----------" | lolcat -F 0.2
	echo -e "===========================================================" | lolcat -F 0.2
    echo -e "OpenSSH            : 22, 143" | lolcat -F 0.2
    echo -e "SSL/TLS            : 443" | lolcat -F 0.2
	echo -e "Dropbear           : 444 , 80 " | lolcat -F 0.2
	echo -e "SquidProxy         : $IP:8080(limit to IP SSH)" | lolcat -F 0.2
	echo -e "badvpn             : badvpn-udpgw port 7200" | lolcat -F 0.2
	echo -e "Webmin             : https://$IP:10000/" | lolcat -F 0.2
	echo -e "OpenVPN            : $IP:81/client.ovpn" | lolcat -F 0.2

	echo -e "${NORMAL}"
    echo -e "${NORMAL}------------------------------------------------------------------${NORMAL}" | lolcat -F 0.2
	echo -e "${NUMBER}Apa yang ingin anda lakukan? ${NUMBER}"| lolcat -F 0.2
	echo -e "${NORMAL}------------------------------------------------------------------${NORMAL}" | lolcat -F 0.2
	echo -e "${NORMAL}"| lolcat -F 0.2
    echo -e "1${NORMAL} Buat/Hapus Akun SSH/OpenVPN (add-del)"| lolcat -F 0.2
    echo -e "2${NORMAL} Panel Akun PPTP VPN (add-pptp)"| lolcat -F 0.2
    echo -e "3${NORMAL} Ganti Password Akun SSH/OpenVPN (user-pass)"| lolcat -F 0.2
    echo -e "4${NORMAL} Ubah Masa Aktif Akun SSH/OpenVPN (expiry-change)" | lolcat -F 0.2
    echo -e "5${NORMAL} Perbarui Akun SSH/OpenVPN (user-renew)" | lolcat -F 0.2
    echo -e "6${NORMAL} Cek Login Dropbear, OpenSSH, PPTP VPN dan OpenVPN (user-login)"| lolcat -F 0.2
    echo -e "7${NORMAL} Monitoring Dropbear (dropmon)" | lolcat -F 0.2
	echo -e "8${NORMAL} Kill Multi-login (user-limit)" | lolcat -F 0.2
	echo -e "9${NORMAL} Daftar Akun dan Tanggal Expired (user-list)" | lolcat -F 0.2
	echo -e "10${NORMAL} Daftar Akun akan Expired Minggu ini (user-expired-list)" | lolcat -F 0.2
	echo -e "11${NORMAL} Daftar Akun Yang Sudah Expired (user-expired)" | lolcat -F 0.2
	echo -e "12${NORMAL} Daftar Akun Aktif (user-active-list)" | lolcat -F 0.2
	echo -e "13${NORMAL} Disable Akun Yang Sudah Expired (disable-user-expired)" | lolcat -F 0.2
	echo -e "14${NORMAL} Delete Akun Yang Sudah Expired (del-user-expired)" | lolcat -F 0.2
	echo -e "15${NORMAL} BANNED Akun SSH/VPN (user-ban)" | lolcat -F 0.2
	echo -e "16${NORMAL} UNBANNED Akun SSH/VPN (user-unban)" | lolcat -F 0.2
	echo -e "17${NORMAL} Restart Dropbear (service dropbear restart)" | lolcat -F 0.2
	echo -e "18${NORMAL} Benchmark (benchmark)" | lolcat -F 0.2
	echo -e "19${NORMAL} Cek Graphic CPU Load dan Memory (mrtg)" | lolcat -F 0.2
	echo -e "20${NORMAL} Memory Usage (ps-mem)" | lolcat -F 0.2
	echo -e "21${NORMAL} Speedtest (speedtest --share)" | lolcat -F 0.2
	echo -e "22${NORMAL} Cek Bandwith VPS (vnstat)" | lolcat -F 0.2
	echo -e "23${NORMAL} Ubah Password VPS (passwd)" | lolcat -F 0.2
	echo -e "24${NORMAL} Reboot Server (reboot)" | lolcat -F 0.2
echo ""  | tee -a log-install.txt
echo -e "${LRED}Tools${NORMAL}"  | tee -a log-install.txt
echo "-----"  | tee -a log-install.txt
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs venet0"  | tee -a log-install.txt
echo "-----"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo -e "${LRED}PANEL MENU${NORMAL}"  | tee -a log-install.txt
echo "------"  | tee -a log-install.txt
echo -e "Silakan Ketik ${LRED}menu ${NORMAL}Untuk Akses Fitur"  | tee -a log-install.txt
echo -e "${LRED}Fitur lain${NORMAL}"  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo -e "${LGREEN}Webmin   : ${NORMAL}http://$MYIP:10000/"  | tee -a log-install.txt
echo -e "${LGREEN}Timezone : ${NORMAL}Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo -e "${LGREEN}Fail2Ban : ${NORMAL}[on]"  | tee -a log-install.txt
echo -e "${LGREEN}(D)DoS Deflate : ${NORMAL}[on]" | tee -a log-install.txt
echo -e "${LGREEN}IPv6     : ${NORMAL}[off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt
echo -e "Reza Adrian , Whatsapp : 081214422324" | lolcat -F 0.2| tee -a log-install.txt

echo ""  | tee -a log-install.txt

echo "-------------------------------------------"  | tee -a log-install.txt
echo "Log Installasi --> /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "-------------------------------------------"  | tee -a log-install.txt
echo -e "${LRED}SILAKAN REBOOT VPS ANDA !${NORMAL}"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt
cd
rm -f /root/Install8.sh
rm -f /root/addpptp.sh
rm -f /root/menu.sh
rm -r /root/fornesia87
rm -r /root/fornesia87.tgz
rm -f /root/speedtest_cli.py
rm -f /root/ps_mem.py
rm -f /root/screenfetch.sh
rm -f /root/daftarip
rm -f /root/webmin_1.831_all.deb
rm   /root/dropbear-2017.75
rm   /root/dropbear-2017.75.tar.bz2
