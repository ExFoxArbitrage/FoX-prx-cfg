#!/bin/sh
random() {
	tr </dev/urandom -dc A-Za-z0-9 | head -c8
	echo
}

array=(1 2 3 4 5 6 7 8 9 0 a b c d e f)
gen64() {
    ip64() {
	    echo "${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}"
		}
		    echo "$1:$(ip64):$(ip64):$(ip64):$(ip64)"
		    }

install_3proxy() {
    URL="https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz"
    wget -qO- $URL | bsdtar -xvf-
    cd 3proxy-0.9.4
    make -f Makefile.Linux
    mkdir -p /usr/local/etc/3proxy/{bin,stat}
    cp bin/3proxy /usr/local/etc/3proxy/bin/
    cp ../init.d/3proxy.sh /etc/init.d/3proxy
    chmod +x /etc/init.d/3proxy
    chkconfig 3proxy on
    cd $WORKDIR
}

gen_3proxy() {
    cat <<EOF
daemon
nscache 65536
stacksize 65536
timeouts 1 5 30 60 180 1800 15 60
maxconn 1000

flush
log /dev/null

users $(awk -F "/" 'BEGIN{ORS="";} {print $1 ":CL:" $2 " "}' ${WORKDATA})

$(awk -F "/" '{print "auth strong cache\n" \
"allow "$1"\n" \
"proxy -n -a -s0 -64 -olSO_REUSEADDR,SO_REUSEPORT -ocTCP_TIMESTAMPS,TCP_NODELAY -osTCP_NODELAY -p"$4" -i"$3" -e"$5"\n" \
"flush\n"}' ${WORKDATA})
EOF
}

gen_proxy_file_for_user() {
    cat >proxy.txt <<EOF
$(awk -F "/" '{print $3":"$4":"$1":"$2}' ${WORKDATA})
EOF
}

upload_proxy() {
    URL=$(curl -s --upload-file proxy.txt https://transfer.sh/proxy.txt)
    echo "Server ip = ${IP4}. Exteranl sub for ip6 = ${IP6}"
    echo "Proxy is ready! Format IP:PORT:LOGIN:PASS"
    echo "Download zip archive from: ${URL}"

}
gen_data() {
    seq $FIRST_PORT $LAST_PORT | while read port; do
        echo "$(random)/$(random)/$IP4/$port/$(gen64 $IP6)"
    done
}

gen_iptables() {
    cat <<EOF
    $(awk -F "/" '{print "iptables -I INPUT -p tcp --dport "$4"  -m state --state NEW -j ACCEPT"}' ${WORKDATA}) 
EOF
}

gen_ifconfig() {
    cat <<EOF
$(awk -F "/" '{print "ifconfig eth0 inet6 add "$5"/64"}' ${WORKDATA})
EOF
}
yum -y install gcc net-tools bsdtar zip >/dev/null

install_3proxy

WORKDIR="/home/proxy-installer"
WORKDATA="${WORKDIR}/data.txt"
mkdir $WORKDIR && cd $_

echo "Your IPv4 address:"
read IPv4
echo "Your IPv6 subnet:"
read IPv6

IP4=${IPv4}
IP6=${IPv6}

echo "Internal ip = ${IP4}. Exteranl sub for ip6 = ${IP6}"

echo "How many proxy do you want to create?"
read COUNT

echo "Port starting proxies:"
read START_PORT

FIRST_PORT=${START_PORT}
LAST_PORT=$(($FIRST_PORT + $COUNT))

gen_data >$WORKDIR/data.txt
gen_iptables >$WORKDIR/boot_iptables.sh
gen_ifconfig >$WORKDIR/boot_ifconfig.sh
chmod +x ${WORKDIR}/boot_*.sh /etc/rc.local

gen_3proxy >/usr/local/etc/3proxy/3proxy.cfg

echo "net.ipv6.conf.eth0.proxy_ndp=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.ip_nonlocal_bind=1" >> /etc/sysctl.conf
echo "vm.max_map_count=95120" >> /etc/sysctl.conf
echo "kernel.pid_max=95120" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_port_range=1024 65000" >> /etc/sysctl.conf
sysctl -p
printf "fs.file-max = 500000" >> /etc/sysctl.conf && printf "hard nofile 500000\n* soft nofile 500000\nroot hard nofile 500000\nroot soft nofile 500000\n* soft nproc 4000\n* hard nproc 16000\nroot - memlock unlimited\nnet.ipv4.tcp_fin_timeout = 10\nnet.ipv4.tcp_max_syn_backlog = 4096\nnet.ipv4,tcp_synack_retries = 3\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 3" >> /etc/security/limits.conf && printf "DefaultLimitDATA=infinity\nDefaultLimitSTACK=infinity\nDefaultLimitCORE=infinity\nDefaultLimitRSS=infinity\nDefaultLimitNOFILE=500000\nDefaultLimitAS=infinity\nDefaultLimitNPROC=500000\nDefaultLimitMEMLOCK=infinity" >> /etc/systemd/system.conf && printf "DefaultLimitDATA=infinity\nDefaultLimitSTACK=infinity\nDefaultLimitCORE=infinity\nDefaultLimitRSS=infinity\nDefaultLimitNOFILE=500000\nDefaultLimitAS=infinity\nDefaultLimitNPROC=500000\nDefaultLimitMEMLOCK=infinity" >> /etc/systemd/user.conf

chmod -R 777 /usr/local/etc/3proxy/

cat >>/etc/rc.local <<EOF
bash ${WORKDIR}/boot_iptables.sh
bash ${WORKDIR}/boot_ifconfig.sh

ulimit -n 999999

service 3proxy start
EOF

bash /etc/rc.local

gen_proxy_file_for_user
upload_proxy
