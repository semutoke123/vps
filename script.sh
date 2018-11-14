ADD MENU + Compiler

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
