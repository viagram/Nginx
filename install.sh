#!/bin/sh
# By viagram <viagram.yang@gmail.com>

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

MY_SCRIPT="$(dirname $(readlink -f $0))/$(basename $0)"

echo -ne "\033[33m"
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
echo -e "\033[0m"

function Check_OS(){
    Text=$(cat /etc/*-release)
    echo ${Text} | egrep -iq "(centos[a-z ]*5|red[a-z ]*hat[a-z ]*5)" && echo centos5 && return
    echo ${Text} | egrep -iq "(centos[a-z ]*6|red[a-z ]*hat[a-z ]*6)" && echo centos6 && return
    echo ${Text} | egrep -iq "(centos[a-z ]*7|red[a-z ]*hat[a-z ]*7)" && echo centos7 && return
    echo ${Text} | egrep -iq "(centos[a-z ]*8|red[a-z ]*hat[a-z ]*8)" && echo centos8 && return
    echo ${Text} | egrep -iq "(Rocky[a-z ]*8|red[a-z ]*hat[a-z ]*8)" && echo rockylinux8 && return
    echo ${Text} | egrep -iq "debian[a-z /]*[0-9]{1,2}" && echo debian && return
    echo ${Text} | egrep -iq "Fedora[a-z ]*[0-9]{1,2}" && echo fedora && return
    echo ${Text} | egrep -iq "OpenWRT[a-z ]*" && echo openwrt && return
    echo ${Text} | egrep -iq "ubuntu[[:space:]]*20\." && echo ubuntu20 && return
    echo ${Text} | egrep -iq "ubuntu" && echo ubuntu && return
}


function printnew(){
    typeset -l CHK
    content=''
    colour=''
    br=0
    for line in "${@}"; do
        echo "${line}" | egrep -iq '^\-[[:graph:]]*' && {
            case "${line}" in
                -black) colour="\033[30m";;
                -red) colour="\033[31m";;
                -green) colour="\033[32m";;
                -yellow) colour="\033[33m";;
                -blue) colour="\033[34m";;
                -purple) colour="\033[35m";;
                -cyan) colour="\033[36m";;
                -white) colour="\033[37m";;
                -a) br=1;;
                *) colour="\033[37m";;
            esac
        } || content+="${line}"
    done
    [[ ${br} -eq 1 ]] && echo -en "${colour}${content}\033[0m" || echo -e "${colour}${content}\033[0m"
}

function doNet(){
    # 以前优化设置来自于网络, 具体用处嘛~~~我也不知道^_^.
    sysctl=/etc/sysctl.conf
    limits=/etc/security/limits.conf
    sed -i '/* soft nofile/d' $limits;echo '* soft nofile 1024000'>>$limits
    sed -i '/* hard nofile/d' $limits;echo '* hard nofile 1024000'>>$limits
    echo "ulimit -SHn 1024000">>/etc/profile
    ulimit -n 1024000
    sed -i '/net.ipv4.ip_forward/d' ${sysctl};echo 'net.ipv4.ip_forward=1'>>${sysctl}
    sed -i '/net.ipv4.conf.default.rp_filter/d' ${sysctl};echo 'net.ipv4.conf.default.rp_filter=1'>>${sysctl}
    sed -i '/net.ipv4.conf.default.accept_source_route/d' ${sysctl};echo 'net.ipv4.conf.default.accept_source_route=0'>>${sysctl}
    sed -i '/kernel.sysrq/d' ${sysctl};echo 'kernel.sysrq=0'>>${sysctl}
    sed -i '/kernel.core_uses_pid/d' ${sysctl};echo 'kernel.core_uses_pid=1'>>${sysctl}
    sed -i '/kernel.msgmnb/d' ${sysctl};echo 'kernel.msgmnb=65536'>>${sysctl}
    sed -i '/kernel.msgmax/d' ${sysctl};echo 'kernel.msgmax=65536'>>${sysctl}
    sed -i '/kernel.shmmax/d' ${sysctl};echo 'kernel.shmmax=68719476736'>>${sysctl}
    sed -i '/kernel.shmall/d' ${sysctl};echo 'kernel.shmall=4294967296'>>${sysctl}
    sed -i '/net.ipv4.tcp_timestamps/d' ${sysctl};echo 'net.ipv4.tcp_timestamps=0'>>${sysctl}
    sed -i '/net.ipv4.tcp_retrans_collapse/d' ${sysctl};echo 'net.ipv4.tcp_retrans_collapse=0'>>${sysctl}
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' ${sysctl};echo 'net.ipv4.icmp_echo_ignore_broadcasts=1'>>${sysctl}
    sed -i '/net.ipv4.conf.all.rp_filter/d' ${sysctl};echo 'net.ipv4.conf.all.rp_filter=1'>>${sysctl}
    sed -i '/fs.inotify.max_user_watches/d' ${sysctl};echo 'fs.inotify.max_user_watches=65536'>>${sysctl}
    sed -i '/net.ipv4.conf.default.promote_secondaries/d' ${sysctl};echo 'net.ipv4.conf.default.promote_secondaries=1'>>${sysctl}
    sed -i '/net.ipv4.conf.all.promote_secondaries/d' ${sysctl};echo 'net.ipv4.conf.all.promote_secondaries=1'>>${sysctl}
    sed -i '/kernel.hung_task_timeout_secs=0/d' ${sysctl};echo 'kernel.hung_task_timeout_secs=0'>>${sysctl}
    sed -i '/fs.file-max/d' ${sysctl};echo 'fs.file-max=1024000'>>${sysctl}
    sed -i '/net.core.wmem_max/d' ${sysctl};echo 'net.core.wmem_max=67108864'>>${sysctl}
    sed -i '/net.core.netdev_max_backlog/d' ${sysctl};echo 'net.core.netdev_max_backlog=32768'>>${sysctl}
    sed -i '/net.core.somaxconn/d' ${sysctl};echo 'net.core.somaxconn=32768'>>${sysctl}
    sed -i '/net.ipv4.tcp_syncookies/d' ${sysctl};echo 'net.ipv4.tcp_syncookies=1'>>${sysctl}
    sed -i '/net.ipv4.tcp_tw_reuse/d' ${sysctl};echo 'net.ipv4.tcp_tw_reuse=1'>>${sysctl}
    sed -i '/net.ipv4.tcp_fin_timeout/d' ${sysctl};echo 'net.ipv4.tcp_fin_timeout=30'>>${sysctl}
    sed -i '/net.ipv4.tcp_keepalive_time/d' ${sysctl};echo 'net.ipv4.tcp_keepalive_time=1200'>>${sysctl}
    sed -i '/net.ipv4.ip_local_port_range/d' ${sysctl};echo 'net.ipv4.ip_local_port_range=1024 65500'>>${sysctl}
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' ${sysctl};echo 'net.ipv4.tcp_max_syn_backlog=8192'>>${sysctl}
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' ${sysctl};echo 'net.ipv4.tcp_max_tw_buckets=6000'>>${sysctl}
    sed -i '/net.ipv4.tcp_fastopen/d' ${sysctl};echo 'net.ipv4.tcp_fastopen=3'>>${sysctl}
    sed -i '/net.ipv4.tcp_rmem/d' ${sysctl};echo 'net.ipv4.tcp_rmem=4096'>>${sysctl}
    sed -i '/net.ipv4.tcp_wmem/d' ${sysctl};echo 'net.ipv4.tcp_wmem=4096'>>${sysctl}
    sed -i '/net.ipv4.tcp_mtu_probing/d' ${sysctl};echo 'net.ipv4.tcp_mtu_probing=1'>>${sysctl}
    sed -i '/net.ipv4.tcp_ecn/d' ${sysctl};echo 'net.ipv4.tcp_ecn = 1' >> ${sysctl}
    sed -i '/net.ipv4.tcp_ecn_fallback/d' ${sysctl};echo 'net.ipv4.tcp_ecn_fallback = 1' >> ${sysctl}
    sysctl -p
    sleep 1
}

#改成北京时间
function check_datetime(){
    if [[ "$(Check_OS)" == "centos7" || "$(Check_OS)" == "centos8" || "$(Check_OS)" == "rockylinux8" ]]; then
        timedatectl set-timezone Asia/Shanghai
    elif [[ "$(Check_OS)" == "centos6" ]]; then
        rm -rf /etc/localtime
        ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    fi
    ntpdate pool.ntp.org >/dev/null 2>&1
}

function install_cmake(){
    printnew -green "安装CMake..."
    which cmake >/dev/null 2>&1 && yum remove -y cmake
    cmake_ver_1=$(curl -#kL https://cmake.org/files/ | egrep -io 'v[0-9]{1,2}\.[0-9]{1,2}' | sort -ruV | head -n1)
    cmake_ver_2=$(curl -#kL https://cmake.org/files/${cmake_ver_1}/ | egrep -io 'cmake-[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}(|-rc5)-linux-x86_64.sh' | sort -ruV | head -n1)
    cmake_down_url="https://cmake.org/files/${cmake_ver_1}/${cmake_ver_2}"
    curl -#kL "${cmake_down_url}" -o "${cmake_ver_2}"
    bash "${cmake_ver_2}" --prefix=/usr/ --exclude-subdir
    rm -f "${cmake_ver_2}"
    source /etc/profile
}

function version_gt() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1";} #大于
function version_ge() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1";} #大于或等于
function version_lt() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1";} #小于
function version_le() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" == "$1";} #小于或等于

#################################################################################################################################################

CUR_DIR="$(dirname $(readlink -f $0))"
NGINX_INPATH="/usr/local/nginx"

# Check If You Are Root
if [[ $EUID -ne 0 ]]; then
    printnew -red "错误: 必须以root权限运行此脚本! "
    cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR}
    exit 1
fi

if [[ "$(Check_OS)" != "rockylinux8" && "$(Check_OS)" != "centos8" && "$(Check_OS)" != "centos7" && "$(Check_OS)" != "centos6" ]]; then
    printnew -red "目前仅支持CentOS6-7-8及Redhat6-7-8系统."
    cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR}
    exit 1
fi

cd ${CUR_DIR}
printnew -green "获取nginx信息..."
#稳定版
#DOWN=$(curl -sk http://nginx.org/en/download.html | egrep -io '<h4>Stable version</h4>[[:print:]]*<h4>Legacy versions</h4>' | egrep -io '/download/nginx-([0-9]{1,2}.){1,3}tar.gz' | sort -Vu)
#开发版
#DOWN=$(curl -sk http://nginx.org/en/download.html | egrep -io '<h4>Mainline version</h4>[[:print:]]*<h4>Stable version</h4>' | egrep -io '/download/nginx-([0-9]{1,2}.){1,3}tar.gz' | sort -Vu)
#自动选择最新版
DOWN=$(curl -sk http://nginx.org/en/download.html | egrep -io '/download/nginx-([0-9]{1,2}.){1,3}tar.gz' | sort -rVu | head -n1)
NAME=$(echo ${DOWN} | egrep -io 'nginx-[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}')
[[ -z ${NAME} ]] && printnew -red "获取nginx信息失败." && cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR} && exit 1

_new_ver=$(echo ${NAME} | egrep -io '[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')
[[ -f ${NGINX_INPATH}/sbin/nginx ]] && chmod +x ${NGINX_INPATH}/sbin/nginx
[[ -x ${NGINX_INPATH}/sbin/nginx ]] && _old_ver=$(${NGINX_INPATH}/sbin/nginx -v 2>&1 | egrep -io '[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')
printnew -green "最新版本: \033[33m${_new_ver}"
if [[ -n ${_old_ver} ]]; then
    printnew -green "已装版本: \033[33m${_old_ver}"
    if version_ge ${_old_ver} ${_new_ver}; then
        printnew -red "检测到系统已安装更新版本的Nginx"
        read -p "输入[y/n]选择是否继续覆盖安装, 默认为n：" is_go
        [[ -z "${is_go}" ]] && is_go='n'
        [[ ${is_go} =~ ^[Nn]$ ]] && printnew -red "用户取消, 程序终止." && cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR} && exit 0
    fi
fi

printnew -green "将进行 ${NAME} 安装."

printnew -green "安装基础依懒软件包..."
yum groupinstall -y "Development Tools"
if [[ "$(Check_OS)" == "centos8" || "$(Check_OS)" == "rockylinux8" ]]; then
    dnf install -y epel-release
    dnf install -y git mercurial gcc gcc-c++ kernel-devel unzip automake make zlib-devel openssl openssl-devel pcre-devel pam-devel curl wget libtool libevent gettext-devel libxml2 libxml2-devel libxslt-devel gd-devel perl-devel perl-ExtUtils-Embed google-perftools-devel
else
    yum install -y epel-release
    yum install -y git mercurial gcc gcc-c++ kernel-devel unzip automake make zlib-devel openssl openssl-devel pcre-devel pam-devel curl wget libtool libevent gettext-devel libxml2 libxslt-devel gd-devel perl-devel perl-ExtUtils-Embed google-perftools-devel ntpdate
fi

printnew -green "下载libmaxminddb源码..."
VERSION=$(curl -sk https://github.com/maxmind/libmaxminddb/releases/latest | egrep -io '/tag/[0-9.]*' | egrep -io '[0-9.]*')
if ! wget -c https://github.com/maxmind/libmaxminddb/releases/download/${VERSION}/libmaxminddb-${VERSION}.tar.gz -O libmaxminddb-${VERSION}.tar.gz --no-check-certificate; then
    printnew -red "下载libmaxminddb-${VERSION}失败."
    rm -rf libmaxminddb*
    exit 1
fi
if ! tar zxf libmaxminddb-${VERSION}.tar.gz; then
    printnew -red "解压libmaxminddb-${VERSION}失败."
    rm -rf libmaxminddb*
    exit 1
fi
printnew -green "编译和安装libmaxminddb..."
cd libmaxminddb-${VERSION}
./configure
if ! make; then
    printnew -red "编译失败."
    rm -rf libmaxminddb*
    exit 1
fi
if ! make install; then
    printnew -red "安装失败."
    rm -rf libmaxminddb*
    exit 1
fi
if ! egrep -i "/usr/local/lib" /etc/ld.so.conf.d/local.conf >/dev/null 2>&1; then
    echo "/usr/local/lib">>/etc/ld.so.conf.d/local.conf
fi
ldconfig >/dev/null 2>&1
cd ..

printnew -green "下载nginx源码..."
if ! wget -O ${NAME}.tar.gz -c http://nginx.org${DOWN} --no-check-certificate; then
    printnew -red "下载nginx源码失败."
    exit 1
fi
if ! tar zxf ${NAME}.tar.gz; then
    printnew -red "解压nginx源码失败."
    exit 1
fi

cd ${NAME}

printnew -green "下载和克隆nginx组件源码..."
#git clone https://github.com/yaoweibin/nginx_tcp_proxy_module.git
[[ -d ngx_http_geoip2_module ]] && rm -rf ngx_http_geoip2_module
if ! git clone https://github.com/leev/ngx_http_geoip2_module.git; then
    printnew -red "克隆ngx_http_geoip2_module源码失败."
    exit 1
fi
[[ -d ngx_http_google_filter_module ]] && rm -rf ngx_http_google_filter_module
if ! git clone https://github.com/cuber/ngx_http_google_filter_module.git; then
    printnew -red "克隆ngx_http_google_filter_module源码失败."
    exit 1
fi
[[ -d ngx_http_substitutions_filter_module ]] && rm -rf ngx_http_substitutions_filter_module
if ! git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git; then
    printnew -red "克隆ngx_http_substitutions_filter_module源码失败."
    exit 1
fi
[[ -d ngx_brotli ]] && rm -rf ngx_brotli
if ! git clone https://github.com/google/ngx_brotli.git; then
    printnew -red "克隆ngx_brotli源码失败."
    exit 1
fi
cd ngx_brotli
git submodule update --init
cd ..
PCRE_URL=$(curl -sk https://ftp.pcre.org/pub/pcre/ | egrep -io 'pcre-[0-9]{1,2}.[0-9]{1,2}.tar.gz' | sort -Vu | awk 'END{print "https://ftp.pcre.org/pub/pcre/"$0}')
PCRE_NAME=$(echo ${PCRE_URL} | egrep -io 'pcre-[0-9]{1,2}.[0-9]{1,2}')
if ! wget -O ${PCRE_NAME}.tar.gz -c ${PCRE_URL} --no-check-certificate; then
    printnew -red "下载pcre源码失败."
    exit 1
fi
if ! tar zxf ${PCRE_NAME}.tar.gz; then
    printnew -red "解压pcre源码失败."
    exit 1
fi
OPENSSL_URL=$(curl -sk https://www.openssl.org/source/ | egrep -io 'openssl-[0-9.]*[a-z]{1}.tar.gz' | sort -rVu | awk 'END{print "https://www.openssl.org/source/"$0}')
OPENSSL_NAME=$(echo ${OPENSSL_URL} | egrep -io 'openssl-[0-9.]*[a-z]{1}')
if ! wget -O ${OPENSSL_NAME}.tar.gz -c ${OPENSSL_URL} --no-check-certificate; then
    printnew -red "下载openssl源码失败."
    exit 1
fi
if ! tar zxf ${OPENSSL_NAME}.tar.gz; then
    printnew -red "解压openssl源码失败."
    exit 1
fi
ZLIB_URL=$(curl -sk https://zlib.net/ | egrep -io 'zlib-([0-9]{1,2}.){3}tar.gz' | sort -Vu | awk '{print "https://zlib.net/"$0}')
ZLIB_NAME=$(echo ${ZLIB_URL} | egrep -io 'zlib-[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')
if ! wget -O ${ZLIB_NAME}.tar.gz -c ${ZLIB_URL} --no-check-certificate; then
    printnew -red "下载zlib源码失败."
    exit 1
fi
if ! tar zxf ${ZLIB_NAME}.tar.gz; then
    printnew -red "解压zlib源码失败."
    exit 1
fi

printnew -green "编译和安装Nginx..."
./configure \
    --prefix=${NGINX_INPATH} \
    --with-pcre=${PCRE_NAME} \
    --with-zlib=${ZLIB_NAME} \
    --with-openssl=${OPENSSL_NAME} \
    --add-module=ngx_brotli \
    --add-module=ngx_http_geoip2_module \
    --add-module=ngx_http_google_filter_module \
    --add-module=ngx_http_substitutions_filter_module \
    --with-file-aio \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-http_v2_module \
    --with-http_sub_module \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module \
    --with-http_addition_module \
    --with-http_xslt_module=dynamic \
    --with-http_image_filter_module=dynamic \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_degradation_module \
    --with-http_slice_module \
    --with-http_perl_module=dynamic \
    --with-http_auth_request_module \
    --with-mail=dynamic \
    --with-mail_ssl_module \
    --with-google_perftools_module

if ! make; then
    printnew -red "编译失败."
    exit 1
fi
if ! make install; then
    printnew -red "安装失败."
    exit 1
fi
cd ..
ln -sf /usr/local/nginx/sbin/nginx /usr/sbin/nginx

printnew -green "下载GeoLite2-Country.mmdb..."
GeoLite2_Name='GeoLite2-Country.tar.gz'
[[ -f ${NGINX_INPATH}/${GeoLite2_Name} ]] && rm -f ${NGINX_INPATH}/${GeoLite2_Name}
if ! wget -O ${NGINX_INPATH}/${GeoLite2_Name} -c https://dnsdian.com/${GeoLite2_Name} --no-check-certificate; then
    printnew -red "下载GeoLite2-Country.mmdb失败."
fi
if ! tar -zxf ${NGINX_INPATH}/${GeoLite2_Name} -C ${NGINX_INPATH}/; then
    printnew -red "解压GeoLite2-Country.mmdb失败."
fi
rm -f ${NGINX_INPATH}/${GeoLite2_Name}

printnew -green "安装和配置Nginx服务..."
cd ${CUR_DIR}
cp -rf 404.html ${NGINX_INPATH}/html/404.html
cp -rf index.html ${NGINX_INPATH}/html/index.html
sed -i 's/zip;/zip ipk apk tar gz tgz xz bz2;/g' ${NGINX_INPATH}/conf/mime.types
if [[ ! -e ${NGINX_INPATH}/conf/frist.chk ]]; then
    cp -rf nginx.conf ${NGINX_INPATH}/conf/nginx.conf
    echo yes>${NGINX_INPATH}/conf/frist.chk
fi

if [[ "$(Check_OS)" == "centos6" ]]; then
    sed -i "s%NGINX_INPATH%${NGINX_INPATH}%g" nginx
    cp -rf nginx /etc/init.d/nginx
    chmod +x /etc/init.d/nginx >/dev/null 2>&1
    chkconfig --add nginx  >/dev/null 2>&1
    chkconfig nginx on >/dev/null 2>&1
    if ! service nginx status >/dev/null 2>&1; then
        if service nginx start; then
            printnew -green "Nginx 启动成功."
        else
            printnew -red "Nginx 启动失败."
        fi
    else
        if service nginx restart; then
            printnew -green "Nginx 重启成功."
        else
            printnew -red "Nginx 重启失败."
        fi
    fi
    
elif [[ "$(Check_OS)" == "centos7" || "$(Check_OS)" == "centos8" || "$(Check_OS)" == "rockylinux8" ]]; then
    sed -i "s%NGINX_INPATH%${NGINX_INPATH}%g" nginx.service
    cp -rf nginx.service /usr/lib/systemd/system/nginx.service
    chmod 754 /usr/lib/systemd/system/nginx.service >/dev/null 2>&1
    systemctl enable nginx.service >/dev/null 2>&1
    systemctl daemon-reload >/dev/null 2>&1
    if ! systemctl status nginx; then
        if systemctl start nginx; then
            printnew -green "Nginx 启动成功."
        else
            printnew -red "Nginx 启动失败."
        fi
    else
        if systemctl restart nginx; then
            printnew -green "Nginx 重启成功."
        else
            printnew -red "Nginx 重启失败."
        fi
    fi
fi

cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR}
