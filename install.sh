#!/bin/sh
# By viagram <viagram.yang@gmail.com>

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

MY_SCRIPT="$(dirname $(readlink -f $0))/$(basename $0)"

echo -e "\033[33m"
cat <<'EOF'

###################################################################
#                     _                                           #
#              __   _(_) __ _  __ _ _ __ __ _ _ __ ___            #
#              \ \ / / |/ _` |/ _` | '__/ _` | '_ ` _ \           #
#               \ V /| | (_| | (_| | | | (_| | | | | | |          #
#                \_/ |_|\__,_|\__, |_|  \__,_|_| |_| |_|          #
#                             |___/                               #
#                                                                 #
###################################################################
EOF
echo -e ""

function Check_OS(){
    if [[ -f /etc/redhat-release ]];then
        if egrep -i "centos.*6\..*" /etc/redhat-release >/dev/null 2>&1;then
            echo 'centos6'
        elif egrep -i "centos.*7\..*" /etc/redhat-release >/dev/null 2>&1;then
            echo 'centos7'
        elif egrep -i "Red.*Hat.*6\..*" /etc/redhat-release >/dev/null 2>&1;then
            echo 'redhat6'
        elif egrep -i "Red.*Hat.*7\..*" /etc/redhat-release >/dev/null 2>&1;then
            echo 'redhat7'
        fi
    elif [[ -f /etc/issue ]];then
        if egrep -i "debian" /etc/issue >/dev/null 2>&1;then
            echo 'debian'
        elif egrep -i "ubuntu" /etc/issue >/dev/null 2>&1;then
            echo 'ubuntu'
        fi
    else
        echo 'unknown'
    fi
}

function printnew(){
    typeset -l CHK
    WENZHI=""
    RIGHT=0
    HUANHANG=0
    for PARSTR in "${@}";do
        CHK="${PARSTR}"
        if echo "${CHK}" | egrep -io "^\-[[:graph:]]*" >/dev/null 2>&1; then
            if [[ "${CHK}" == "-black" ]]; then
                COLOUR="\033[30m"
            elif [[ "${CHK}" == "-red" ]]; then
                COLOUR="\033[31m"
            elif [[ "${CHK}" == "-green" ]]; then
                COLOUR="\033[32m"
            elif [[ "${CHK}" == "-yellow" ]]; then
                COLOUR="\033[33m"
            elif [[ "${CHK}" == "-blue" ]]; then
                COLOUR="\033[34m"
            elif [[ "${CHK}" == "-purple" ]]; then
                COLOUR="\033[35m"
            elif [[ "${CHK}" == "-cyan" ]]; then
                COLOUR="\033[36m"
            elif [[ "${CHK}" == "-white" ]]; then
                COLOUR="\033[37m"
            elif [[ "${CHK}" == "-a" ]]; then
                HUANHANG=1
            elif [[ "${CHK}" == "-r" ]]; then
                RIGHT=1
            fi
        else
            WENZHI+="${PARSTR}"
        fi
    done
    COUNT=$(echo -n "${WENZHI}" | wc -L)
    if [[ ${RIGHT} -eq 1 ]];then
        tput cup $(tput lines) $[$(tput cols)-${COUNT}]
        printf "${COLOUR}%b%-${COUNT}s" "${WENZHI}"
        tput cup $(tput lines) 0
    else
        tput cup $(tput lines) 0
        if [[ ${HUANHANG} -eq 1 ]];then
            printf "${COLOUR}%b%-${COUNT}s" "${WENZHI}"
            tput cup $(tput lines) ${COUNT}
        else
            printf "${COLOUR}%b%-${COUNT}s\033[0m\n" "${WENZHI}"
        fi
    fi
}

function OptNET(){
    # 以前优化设置来自于网络, 具体用处嘛~~~我也不知道^_^.
    sysctl=/etc/sysctl.conf
    limits=/etc/security/limits.conf
        sed -i '/* soft nofile/d' $limits; echo '* soft nofile 512000'>>$limits
    sed -i '/* hard nofile/d' $limits; echo '* hard nofile 1024000'>>$limits
    ulimit -n 512000
    sed -i '/net.ipv4.ip_forward/d' $sysctl; echo 'net.ipv4.ip_forward=0'>>$sysctl
    sed -i '/net.ipv4.conf.default.rp_filter/d' $sysctl; echo 'net.ipv4.conf.default.rp_filter=1'>>$sysctl
    sed -i '/net.ipv4.conf.default.accept_source_route/d' $sysctl; echo 'net.ipv4.conf.default.accept_source_route=0'>>$sysctl
    sed -i '/kernel.sysrq/d' $sysctl; echo 'kernel.sysrq=0'>>$sysctl
    sed -i '/kernel.core_uses_pid/d' $sysctl; echo 'kernel.core_uses_pid=1'>>$sysctl
    sed -i '/kernel.msgmnb/d' $sysctl; echo 'kernel.msgmnb=65536'>>$sysctl
    sed -i '/kernel.msgmax/d' $sysctl; echo 'kernel.msgmax=65536'>>$sysctl
    sed -i '/kernel.shmmax/d' $sysctl; echo 'kernel.shmmax=68719476736'>>$sysctl
    sed -i '/kernel.shmall/d' $sysctl; echo 'kernel.shmall=4294967296'>>$sysctl
    sed -i '/net.ipv4.tcp_timestamps/d' $sysctl; echo 'net.ipv4.tcp_timestamps=1'>>$sysctl
    sed -i '/net.ipv4.tcp_retrans_collapse/d' $sysctl; echo 'net.ipv4.tcp_retrans_collapse=0'>>$sysctl
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' $sysctl; echo 'net.ipv4.icmp_echo_ignore_broadcasts=1'>>$sysctl
    sed -i '/net.ipv4.conf.all.rp_filter/d' $sysctl; echo 'net.ipv4.conf.all.rp_filter=1'>>$sysctl
    sed -i '/fs.inotify.max_user_watches/d' $sysctl; echo 'fs.inotify.max_user_watches=65536'>>$sysctl
    sed -i '/net.ipv4.conf.default.promote_secondaries/d' $sysctl; echo 'net.ipv4.conf.default.promote_secondaries=1'>>$sysctl
    sed -i '/net.ipv4.conf.all.promote_secondaries/d' $sysctl; echo 'net.ipv4.conf.all.promote_secondaries=1'>>$sysctl
    sed -i '/kernel.hung_task_timeout_secs=0/d' $sysctl; echo 'kernel.hung_task_timeout_secs=0'>>$sysctl
    sed -i '/fs.file-max/d' $sysctl; echo 'fs.file-max=1024000'>>$sysctl
    sed -i '/net.core.wmem_max/d' $sysctl; echo 'net.core.wmem_max=67108864'>>$sysctl
    sed -i '/net.core.netdev_max_backlog/d' $sysctl; echo 'net.core.netdev_max_backlog=250000'>>$sysctl
    sed -i '/net.core.somaxconn/d' $sysctl; echo 'net.core.somaxconn=4096'>>$sysctl
    sed -i '/net.ipv4.tcp_syncookies/d' $sysctl; echo 'net.ipv4.tcp_syncookies=1'>>$sysctl
    sed -i '/net.ipv4.tcp_tw_reuse/d' $sysctl; echo 'net.ipv4.tcp_tw_reuse=1'>>$sysctl
    sed -i '/net.ipv4.tcp_fin_timeout/d' $sysctl; echo 'net.ipv4.tcp_fin_timeout=30'>>$sysctl
    sed -i '/net.ipv4.tcp_keepalive_time/d' $sysctl; echo 'net.ipv4.tcp_keepalive_time=1200'>>$sysctl
    sed -i '/net.ipv4.ip_local_port_range/d' $sysctl; echo 'net.ipv4.ip_local_port_range=10000'>>$sysctl
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' $sysctl; echo 'net.ipv4.tcp_max_syn_backlog=8192'>>$sysctl
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' $sysctl; echo 'net.ipv4.tcp_max_tw_buckets=5000'>>$sysctl
    sed -i '/net.ipv4.tcp_fastopen/d' $sysctl; echo 'net.ipv4.tcp_fastopen=3'>>$sysctl
    sed -i '/net.ipv4.tcp_rmem/d' $sysctl; echo 'net.ipv4.tcp_rmem=4096'>>$sysctl
    sed -i '/net.ipv4.tcp_wmem/d' $sysctl; echo 'net.ipv4.tcp_wmem=4096'>>$sysctl
    sed -i '/net.ipv4.tcp_mtu_probing/d' $sysctl; echo 'net.ipv4.tcp_mtu_probing=1'>>$sysctl
    #sed -i '/net.core.default_qdisc/d' $sysctl; echo 'net.core.default_qdisc=fq_codel'>>$sysctl
    #sed -i '/net.ipv4.tcp_congestion_control/d' $sysctl; echo 'net.ipv4.tcp_congestion_control=nanqinlang'>>$sysctl
    sysctl -p
}

#改成北京时间
function check_datetime(){
    if [[ "$(Check_OS)" == "centos7" ]];then
        timedatectl set-timezone Asia/Shanghai
    elif [[ "$(Check_OS)" == "centos6" ]];then
        rm -rf /etc/localtime
        ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    fi
    ntpdate cn.pool.ntp.org >/dev/null 2>&1
}

# Check If You Are Root
if [[ $EUID -ne 0 ]]; then
    printnew -red "错误: 必须以root权限运行此脚本! "
    exit 1
fi

NGINX_INPATH=/usr/local/nginx
#################################################################################################################################################

if [[ "$(Check_OS)" != "centos7" && "$(Check_OS)" != "centos6" && "$(Check_OS)" != "redhat7" && "$(Check_OS)" != "redhat6" ]]; then
    printnew -red "目前仅支持CentOS6-7及Redhat6-7系统."
    exit 1
fi

printnew -green "安装基础依懒软件包..."
yum groupinstall -y 'Development Tools'
yum -y install libtool libevent gettext-devel git wget unzip tar ntpdate gcc gcc-c++ epel-release kernel-devel unzip automake make zlib-devel openssl openssl-devel pcre-devel pam-devel curl net-tools

cur_dir=${PWD}/nginx_install
if [[ -d "${cur_dir}" ]]; then
    rm -rf ${cur_dir}
fi
mkdir -p ${cur_dir} && cd $cur_dir

printnew -green "克隆libmaxminddb源码..."
if ! git clone --recursive https://github.com/maxmind/libmaxminddb; then
    printnew -red "克隆libmaxminddb源码失败."
    exit 1
fi
cd libmaxminddb
printnew -green "编译和安装libmaxminddb..."
./bootstrap
./configure
if ! make; then
    printnew -red "编译失败."
    exit 1
fi
if ! make install; then
    printnew -red "安装失败."
    exit 1
fi
if ! egrep -i "/usr/local/lib" /etc/ld.so.conf.d/local.conf >/dev/null 2>&1; then
    echo "/usr/local/lib">>/etc/ld.so.conf.d/local.conf
fi
ldconfig >/dev/null 2>&1
cd ..

DOWN=$(curl -sk http://nginx.org/en/download.html | egrep -io '<h4>Stable version</h4>[[:print:]]*<h4>Legacy versions</h4>' | egrep -io '/download/nginx-[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}\.tar\.g[z$]' | head -n 1)
NAME=$(echo ${DOWN} | egrep -io 'nginx-[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}')
if [[ -z ${NAME} ]]; then
    printnew -red "获取nginx信息失败."
    exit 1
fi
if ! wget -O ${NAME}.tar.gz -c http://nginx.org${DOWN} --no-check-certificate; then
    printnew -red "下载nginx源码失败."
    exit 1
fi
if ! tar zxf ${NAME}.tar.gz; then
    printnew -red "解压nginx源码失败."
    exit 1
fi
cd ${NAME}

#git clone https://github.com/yaoweibin/nginx_tcp_proxy_module.git
if ! git clone https://github.com/leev/ngx_http_geoip2_module.git; then
    printnew -red "克隆ngx_http_geoip2_module源码失败."
    exit 1
fi
if ! git clone https://github.com/cuber/ngx_http_google_filter_module.git; then
    printnew -red "克隆ngx_http_google_filter_module源码失败."
    exit 1
fi
if ! git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git; then
    printnew -red "克隆ngx_http_substitutions_filter_module源码失败."
    exit 1
fi

if ! wget -O pcre-8.41.tar.gz -c https://ftp.pcre.org/pub/pcre/pcre-8.41.tar.gz --no-check-certificate; then
    printnew -red "下载pcre源码失败."
    exit 1
fi
if ! tar zxf pcre-8.41.tar.gz; then
    printnew -red "解压pcre源码失败."
    exit 1
fi
if ! wget -O openssl-1.1.0f.tar.gz -c https://www.openssl.org/source/openssl-1.1.0f.tar.gz --no-check-certificate; then
    printnew -red "下载openssl源码失败."
    exit 1
fi
if ! tar zxf openssl-1.1.0f.tar.gz; then
if ! wget -O zlib-1.2.11.tar.gz -c https://zlib.net/zlib-1.2.11.tar.gz --no-check-certificate; then
    printnew -red "下载zlib源码失败."
    exit 1
fi
if ! tar zxf zlib-1.2.11.tar.gz; then
    printnew -red "解压zlib源码失败."
    exit 1
fi

printnew -green "编译和安装Nginx..."
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_v2_module \
    --with-http_sub_module \
    --with-http_ssl_module \
    --with-http_sub_module \
    --with-http_realip_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module  \
    --with-pcre=pcre-8.41 \
    --with-zlib=zlib-1.2.11 \
    --with-openssl=openssl-1.1.0f \
    --add-module=ngx_http_geoip2_module \
    --add-module=ngx_http_google_filter_module \
    --add-module=ngx_http_substitutions_filter_module \
    --prefix=${NGINX_INPATH}
if ! make; then
    printnew -red "编译失败."
    exit 1
fi
if ! make install; then
    printnew -red "安装失败."
    exit 1
fi
cd ..

printnew -green "下载GeoLite2-Country.mmdb..."
[[ -f ${NGINX_INPATH}/GeoLite2-Country.mmdb.gz ]] && rm -f ${NGINX_INPATH}/GeoLite2-Country.mmdb.gz
if ! wget -O ${NGINX_INPATH}/GeoLite2-Country.mmdb.gz -c http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz --no-check-certificate; then
    printnew -red "下载GeoLite2-Country.mmdb失败."
    exit 1
fi
if ! gunzip -f ${NGINX_INPATH}/GeoLite2-Country.mmdb.gz; then
    printnew -red "解压GeoLite2-Country.mmdb失败."
    exit 1
else
    rm -f ${NGINX_INPATH}/GeoLite2-Country.mmdb.gz
fi

printnew -green "下载和安装Nginx服务..."
if [[ "$(Check_OS)" == "centos6" || "$(Check_OS)" == "redhat6" ]];then
    if ! wget -O nginx -c  https://raw.githubusercontent.com/viagram/Nginx/master/CentOS-6 --no-check-certificate; then
        printnew -red "下载Nginx服务配置失败."
        exit 1
    fi
    sed -i "s/NGINX_INPATH/${NGINX_INPATH}/g" nginx
    \cp -f nginx /etc/init.d/nginx
    chmod 775 /etc/init.d/nginx >/dev/null 2>&1
    chkconfig --add nginx  >/dev/null 2>&1
    chkconfig nginx on >/dev/null 2>&1
elif [[ "$(Check_OS)" == "centos7" || "$(Check_OS)" == "redhat7" ]];then
    if ! wget -O nginx.service -c  https://raw.githubusercontent.com/viagram/Nginx/master/CentOS-7 --no-check-certificate; then
        printnew -red "下载Nginx服务配置失败."
        exit 1
    fi
    sed -i "s/NGINX_INPATH/${NGINX_INPATH}/g" nginx.service
    \cp -f nginx.service /usr/lib/systemd/system/nginx.service
    chmod 754 /usr/lib/systemd/system/nginx.service >/dev/null 2>&1
    systemctl enable nginx.service
    systemctl daemon-reload
fi
if ! wget -O 404.html -c  https://raw.githubusercontent.com/viagram/Nginx/master/404.html --no-check-certificate; then
    printnew -red "下载404.html失败."
fi
\cp -f 404.html ${NGINX_INPATH}/html/404.html
if ! wget -O index.html -c  https://raw.githubusercontent.com/viagram/Nginx/master/index.html --no-check-certificate; then
    printnew -red "下载index.html失败."
fi
\cp -f index.html ${NGINX_INPATH}/html/index.html
if ! wget -O nginx.conf -c  https://raw.githubusercontent.com/viagram/Nginx/master/nginx.conf --no-check-certificate; then
    printnew -red "下载index.html失败."
fi
\cp -f nginx.conf ${NGINX_INPATH}/conf/nginx.conf

if [[ "$(Check_OS)" == "centos6" || "$(Check_OS)" == "redhat6" ]];then
    service nginx restart
elif [[ "$(Check_OS)" == "centos7" || "$(Check_OS)" == "redhat7" ]];then
    systemctl start nginx
fi





