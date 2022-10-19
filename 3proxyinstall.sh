apt-get install gcc make git -y
wget --no-check-certificate -O 3proxy.tar.gz https://github.com/ExFoxArbitrage/3proxy/raw/main/3proxy.tar.gz
tar xzf 3proxy.tar.gz
cd 3proxy
make -f Makefile.Linux
cd src
mkdir /etc/3proxy/
mv 3proxy /etc/3proxy/
cd /etc/3proxy/
wget --no-check-certificate https://github.com/ExFoxArbitrage/3proxy/blob/main/3proxy.cfg
chmod 600 /etc/3proxy/3proxy.cfg
mkdir /var/log/3proxy/
wget --no-check-certificate https://github.com/ExFoxArbitrage/3proxy/blob/main/.proxyauth
chmod 600 /etc/3proxy/.proxyauth
cd /etc/init.d/
wget --no-check-certificate  https://github.com/ExFoxArbitrage/3proxy/blob/main/3proxy
chmod  +x /etc/init.d/3proxy
update-rc.d 3proxy defaults
