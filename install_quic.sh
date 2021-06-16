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
    if echo ${Text} | egrep -io "(centos[a-z ]*5|red[a-z ]*hat[a-z ]*5)" >/dev/null 2>&1; then echo centos5
    elif echo ${Text} | egrep -io "(centos[a-z ]*6|red[a-z ]*hat[a-z ]*6)" >/dev/null 2>&1; then echo centos6
    elif echo ${Text} | egrep -io "(centos[a-z ]*7|red[a-z ]*hat[a-z ]*7)" >/dev/null 2>&1; then echo centos7
    elif echo ${Text} | egrep -io "(centos[a-z ]*8|red[a-z ]*hat[a-z ]*8)" >/dev/null 2>&1; then echo centos8
    elif echo ${Text} | egrep -io "(Rocky[a-z ]*8|red[a-z ]*hat[a-z ]*8)" >/dev/null 2>&1; then echo rockylinux8
    elif echo ${Text} | egrep -io "Fedora[a-z ]*[0-9]{1,2}" >/dev/null 2>&1; then echo fedora
    elif echo ${Text} | egrep -io "debian[a-z /]*[0-9]{1,2}" >/dev/null 2>&1; then echo debian
    elif echo ${Text} | egrep -io "ubuntu" >/dev/null 2>&1; then echo ubuntu
   fi
}

function printnew(){
    typeset -l CHK
    WENZHI=""
    COLOUR=""
    HUANHANG=0
    for PARSTR in "${@}"; do
        CHK="${PARSTR}"
        if echo "${CHK}" | egrep -io "^\-[[:graph:]]*" >/dev/null 2>&1; then
            case "${CHK}" in
                -black) COLOUR="\033[30m";;
                #-red) COLOUR="\033[41;37m";;
                -red) COLOUR="\033[31m";;
                -green) COLOUR="\033[32m";;
                -yellow) COLOUR="\033[33m";;
                -blue) COLOUR="\033[34m";;
                -purple) COLOUR="\033[35m";;
                -cyan) COLOUR="\033[36m";;
                -white) COLOUR="\033[37m";;
                -a) HUANHANG=1;;
                *) COLOUR="\033[37m";;
            esac
        else
            WENZHI+="${PARSTR}"
        fi
    done
    if [[ ${HUANHANG} -eq 1 ]]; then
        printf "${COLOUR}%b%s \033[0m" "${WENZHI}"
    else
        printf "${COLOUR}%b%s\033[0m\n" "${WENZHI}"
    fi
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

####################################################################################################################
# Check If You Are Root
if [[ ${EUID} -ne 0 ]]; then
    printnew -red "错误: 必须以root权限运行此脚本! "
    cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR}
    exit 1
fi

if [[ "$(Check_OS)" != "rockylinux8" && "$(Check_OS)" != "centos8" && "$(Check_OS)" != "centos7" && "$(Check_OS)" != "centos6" ]]; then
    printnew -red "目前仅支持CentOS6-7-8及Redhat6-7-8系统."
    cd ${CUR_DIR}/.. && rm -rf ${CUR_DIR}
    exit 1
fi

check_datetime
doNet

[[ ! -f /usr/local/lib/libmaxminddb.so ]] && {
    yum install gcc gcc-c++ make
    printnew -green "下载libmaxminddb源码..."
    libmaxminddb_name=$(curl -skL https://github.com/maxmind/libmaxminddb/releases/latest | egrep -io 'libmaxminddb-([0-9\.]{1,3}){2,}.tar.gz' | sort -u)
    libmaxminddb_ver=$(echo ${libmaxminddb_name} | egrep -io '([0-9\.]{1,3}){2}[0-9]{1,3}')
    if ! wget -c https://github.com/maxmind/libmaxminddb/releases/download/${libmaxminddb_ver}/${libmaxminddb_name} -O ${libmaxminddb_name} --no-check-certificate; then
        printnew -red "下载${libmaxminddb_name}失败."
        rm -rf libmaxminddb*
        exit 1
    fi
    if ! tar zxf ${libmaxminddb_name}; then
        printnew -red "解压${libmaxminddb_name}失败."
        rm -rf libmaxminddb*
        exit 1
    fi
    printnew -green "编译和安装libmaxminddb..."
    cd libmaxminddb-${libmaxminddb_ver}
    ./configure
    if ! make -j5; then
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
    rm -rf libmaxminddb*
}

! which nginx >/dev/null 2>&1 && {
    curl -skL https://codeload.github.com/viagram/Nginx/tar.gz/master | tar -zxv && sh Nginx-master/install.sh
}
nginx_file=$(cat /usr/lib/systemd/system/nginx.service | egrep -i 'ExecStart=' | awk '{print $1}' | cut -d= -f 2)
nginx_path=$(echo ${nginx_file} | sed 's/nginx$//g')
mv -f ${nginx_file} ${nginx_file}_old
curl -skL https://dnsdian.com/nginx.tgz | tar -zxvC ${nginx_path} && chmod +x ${nginx_file} || curl -skL https://dnsdian.com/nginx.tgz | tar -zxvC ${nginx_path} && chmod +x ${nginx_file}
systemctl restart nginx
####################################### THE CODE END ##################################################
