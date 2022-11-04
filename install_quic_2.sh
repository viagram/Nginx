#!/bin/bash
PATH=${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

function get_cron(){
    cron_list=$(crontab -l 2>&1 | sed 's/^[[:alpha:][:blank:]]*//g' | sed '/^$/d')
    [[ -n ${cron_list} ]] && echo "${cron_list}\n"
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

function Check_OS(){
    Text=$(cat /etc/*-release)
    echo "${Text}" | egrep -iq "(centos[a-z ]*5|red[a-z ]*hat[a-z ]*5)" && echo centos5 && return
    echo "${Text}" | egrep -iq "(centos[a-z ]*6|red[a-z ]*hat[a-z ]*6)" && echo centos6 && return
    echo "${Text}" | egrep -iq "(centos[a-z ]*7|red[a-z ]*hat[a-z ]*7)" && echo centos7 && return
    echo "${Text}" | egrep -iq "(centos[a-z ]*8|red[a-z ]*hat[a-z ]*8)" && echo centos8 && return
    echo "${Text}" | egrep -iq "Rocky Linux release [0-9]{1,2}\.[0-9]{1,2}" && echo rockylinux && return
    echo "${Text}" | egrep -iq "debian[a-z /]*[0-9]{1,2}" && echo debian && return
    echo "${Text}" | egrep -iq "Fedora[a-z ]*[0-9]{1,2}" && echo fedora && return
    echo "${Text}" | egrep -iq "OpenWRT[a-z ]*" && echo openwrt && return
    echo "${Text}" | egrep -iq "ubuntu[[:space:]]*20\." && echo ubuntu20 && return
    echo "${Text}" | egrep -iq "ubuntu" && echo ubuntu && return
}

function version_gt() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1";} #大于
function version_ge() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1";} #大于或等于
function version_lt() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1";} #小于
function version_le() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" == "$1";} #小于或等于

function install_cmake(){
    which cmake >/dev/null 2>&1 && {
        cmake_ver=$(cmake --version | head -n1 | awk '{print $3}')
        ${CMD} remove -y cmake
    }
    [[ -z ${cmake_ver} ]] && cmake_ver=0.0.0
    version_lt ${cmake_ver} 3.10.0 && {
        cmake_ver_1=$(curl -skL https://cmake.org/files/ | egrep -io 'v[0-9]{1,2}\.[0-9]{1,2}' | sort -ruV | head -n1)
        cmake_ver_2=$(curl -skL https://cmake.org/files/${cmake_ver_1}/ | egrep -io 'cmake-[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}(|-[0-9a-z]{1,3})-linux-x86_64.sh' | sort -ruV | head -n1)
        cmake_down_url="https://cmake.org/files/${cmake_ver_1}/${cmake_ver_2}"
        curl -skL "${cmake_down_url}" -o "${cmake_ver_2}"
        bash "${cmake_ver_2}" --prefix=/usr/ --exclude-subdir
        rm -f "${cmake_ver_2}"
        source /etc/profile
    }
}

function install_gcc2(){
    which gcc >/dev/null 2>&1 && {
        gcc_ver=$(gcc --version | egrep -i '(gcc)' | awk '{print $3}')
    }
    [[ -z ${gcc_ver} ]] && gcc_ver=0.0.0
    version_lt ${gcc_ver} 8.0.0 && {
        LIST=$(curl -skL https://mirrors.ustc.edu.cn/gnu/gcc/ | egrep -io 'gcc-[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}' | sort -Vur | head -n 1 | awk '{print "https://mirrors.ustc.edu.cn/gnu/gcc/"$0"/"}')
        NAME=$(curl -skL ${LIST} | egrep -io 'gcc-([0-9]{1,2}\.){1,3}tar.gz' | sort -Vur | awk '{print $0}')
        DIRS=${NAME%.tar.gz*}
        [[ -e ${NAME} ]] && rm -rf ${NAME}
        wget -O ${NAME} -c ${LIST}${NAME} --no-check-certificate
        tar zxvf ${NAME}
        cd ${DIRS}
        ./contrib/download_prerequisites
        ./configure --prefix=/usr/ --enable-checking=release --enable-languages=c,c++ --disable-multilib
        make -j5  #等50分钟左右
        make install
        cd ..
        rm -rf ${DIRS}*
    }
}

function install_gcc(){
    source /opt/rh/devtoolset-${gcc_version}/enable >/dev/null 2>&1
    which gcc >/dev/null 2>&1 && {
        gcc_ver=$(gcc --version | egrep -i '(gcc)' | awk '{print $3}')
    }
    [[ -z ${gcc_ver} ]] && gcc_ver=0.0.0
    version_lt ${gcc_ver} 8.0.0 && {
        gcc_version=$(curl -4skL# https://access.redhat.com/documentation/en-us/red_hat_developer_toolset | egrep -io '/documentation/en-us/red_hat_developer_toolset/[0-9]{1,3}' | egrep -io '[0-9]{1,3}' | sort -ruV | head -n1)
        ${CMD} install centos-release-scl -y
        ${CMD} install devtoolset-${gcc_version} -y
        source /opt/rh/devtoolset-${gcc_version}/enable
    }
}

function install_golang(){
    which go >/dev/null 2>&1 && {
        go_ver=$(go version | awk '{print $3}' | egrep -io '([0-9\.]{1,3}){2}[0-9]{1,3}')
    }
    [[ -z ${go_ver} ]] && go_ver=0.0.0
    version_lt ${go_ver} 1.15.0 && {
        go_name=$(curl -skL https://golang.org/dl/ | egrep -io 'go[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.linux-amd64.tar.gz' | sort -uVr | head -n1)
        [[ -e ${go_name} ]] && rm -rf ${go_name}
        wget -O ${go_name} -c https://golang.org/dl/${go_name} --no-check-certificate
        rm -rf /usr/local/go && tar -zxvf ${go_name} -C /usr/local
        ln -sf /usr/local/go/bin/go /usr/bin/go
        sed -i '/GOROOT/d' /etc/profile
        sed -i '/GOPATH/d' /etc/profile
        sed -i '/GObin/d' /etc/profile
        echo 'export GOROOT=/usr/local/go' >> /etc/profile
        echo 'export GOPATH=/usr/local/go/bin' >> /etc/profile
        echo 'export GOBIN=$GOROOT/bin' >> /etc/profile
        echo 'export PATH=$PATH:${GOROOT}:${GOPATH}:${GOBIN}' >> /etc/profile
        rm -rf ${go_name}
        source /etc/profile
    }
}

function install_libmaxminddb(){
    [[ ! -f /usr/local/lib/libmaxminddb.so ]] && {
        printnew -green "下载libmaxminddb源码..."
        libmaxminddb_name=$(curl -4skL "https://api.github.com/repos/maxmind/libmaxminddb/releases/latest" | jq -r .assets[].name)
        libmaxminddb_ver=$(echo ${libmaxminddb_name} | egrep -io '([0-9\.]{1,3}){2}[0-9]{1,3}')
        if ! wget -c https://github.com/maxmind/libmaxminddb/releases/download/${libmaxminddb_ver}/${libmaxminddb_name} -O ${libmaxminddb_name} --no-check-certificate; then
            printnew -red "下载${libmaxminddb_name}失败."
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
}

function install_boringssl(){
    breakdir=$(pwd)
    [[ ! -f /usr/local/src/boringssl/.openssl/include/openssl/ssl.h ]] && {
        cd /usr/local/src/
        if git clone https://github.com/google/boringssl.git; then
            cd boringssl && mkdir build && cd build && cmake .. && make && cd ../
            mkdir -p .openssl/lib && cd .openssl && ln -s ../include . && cd ../
            cp build/crypto/libcrypto.a build/ssl/libssl.a .openssl/lib
            touch /usr/local/src/boringssl/.openssl/include/openssl/ssl.h
        fi
    }
    cd ${breakdir}
}

function Install_quictls(){
    breakdir=$(pwd)
    [[ ! -f /usr/local/src/quictls/.openssl/include/openssl/ssl.h ]] && {
        cd /usr/local/src/
        if git clone https://github.com/quictls/openssl.git quictls; then
            cd quictls
            ./Configure no-shared enable-zlib enable-ec_nistp_64_gcc_128 --prefix=/usr/local/src/quictls --openssldir=/usr/local/src/quictls
            make install_dev
            mkdir -p .openssl && cd .openssl && \
            ln -s ../lib64 lib && ln -s ../include include
            touch /usr/local/src/quictls/.openssl/include/openssl/ssl.h
        fi
    }
    cd ${breakdir}
}

function check_CMD(){
    [[ -z ${1} ]] && return
    ! which ${1} >/dev/null 2>&1 && {
        [[ ${1} == 'hg' ]] && ${CMD} install -y mercurial || ${CMD} install -y ${1}
    }
}
##################################################################################################################################################
[[ "$(Check_OS)" == "centos6" || "$(Check_OS)" == "centos7" ]] && CMD=yum
[[ "$(Check_OS)" == "centos8" || "$(Check_OS)" == 'fedora' || "$(Check_OS)" == "rockylinux" ]] && CMD=dnf
[[ "$(Check_OS)" == "ubuntu20" || "$(Check_OS)" == "ubuntu" || "$(Check_OS)" == "debian" ]] && CMD=apt


${CMD} install -y automake bzip2 curl epel-release gcc gcc-c++ gd-devel git glibc glibc-devel glibc-headers google-perftools-devel hg kernel-devel libaio libaio-devel \
libcom_err.so.2 libcrypt.so.1 libc.so.6 libdl.so.2 libevent libfreebl3.so libgcc_s.so.1 libgssapi_krb5.so.2 libk5crypto.so.3 libkeyutils.so.1 libkrb5.so.3 libkrb5support.so.0 \
libm.so.6 libpthread.so.0 libresolv.so.2 librt.so.1 libselinux.so.1 libstdc++.so.6 libunwind libxml2 libxml2-devel libxslt libxslt-devel libz.so.1 make ncurses* openssl openssl-devel pam-devel pcre-devel perl-devel perl-ExtUtils-Embed tar unzip wget zlib* zlib-devel

work_path=$(dirname $(readlink -f $0))

check_CMD curl
check_CMD wget
check_CMD git
check_CMD make
check_CMD hg
check_CMD tar

install_golang
install_cmake
install_gcc
install_libmaxminddb
#install_boringssl
Install_quictls

cd ${work_path}
[[ -e nginx-quic ]] && rm -rf nginx-quic
! hg clone -b quic https://hg.nginx.org/nginx-quic && ! hg clone -b quic http://hg.nginx.org/nginx-quic 
cd nginx-quic

printnew -green "下载和克隆nginx组件源码..."
#git clone https://github.com/yaoweibin/nginx_tcp_proxy_module.git
[[ -d ngx_http_geoip2_module ]] && rm -rf ngx_http_geoip2_module
if ! git clone https://github.com/leev/ngx_http_geoip2_module.git; then
    printnew -red "克隆ngx_http_geoip2_module源码失败."
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

PCRE_URL=$(curl -4sk https://sourceforge.net/projects/pcre/files/latest/download | egrep -io 'https://[[:graph:]]*' | cut -d';' -f1 | sed 's/&amp$//g;s/.zip/.tar.gz/g' | egrep -i '/8.45/')
PCRE_NAME=$(echo ${PCRE_URL} | cut -d? -f1 | egrep -io 'pcre-[0-9]{1,2}.[0-9]{1,2}')
if ! wget -O ${PCRE_NAME}.tar.gz -c "${PCRE_URL}" --no-check-certificate; then
    printnew -red "下载pcre源码失败."
    exit 1
fi
if ! tar zxf ${PCRE_NAME}.tar.gz; then
    printnew -red "解压pcre源码失败."
    exit 1
fi
ZLIB_URL=$(curl -4sk https://zlib.net/ | egrep -io 'zlib-([0-9]{1,2}.){3}tar.gz' | sort -Vu | awk '{print "https://zlib.net/"$0}')
ZLIB_NAME=$(echo ${ZLIB_URL} | egrep -io 'zlib-[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')
if ! wget -O ${ZLIB_NAME}.tar.gz -c ${ZLIB_URL} --no-check-certificate; then
    printnew -red "下载zlib源码失败."
    exit 1
fi
if ! tar zxf ${ZLIB_NAME}.tar.gz; then
    printnew -red "解压zlib源码失败."
    exit 1
fi

#    --add-module=ngx_brotli \
printnew -green "配置nginx-quic..."
./auto/configure --with-http_v3_module \
    --with-pcre=${PCRE_NAME} \
    --with-pcre-jit \
    --with-zlib=${ZLIB_NAME} \
    --add-module=ngx_http_geoip2_module \
    --add-module=ngx_http_substitutions_filter_module \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-stream \
    --with-stream_quic_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-http_v2_module \
    --with-http_v3_module \
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
    --with-google_perftools_module \
    --with-openssl=/usr/local/src/quictls/ \
    --with-cc-opt="-O3 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -fPIC"
    #--with-cc-opt="-I/usr/local/src/boringssl/include -fPIC" \
    #--with-ld-opt="-L/usr/local/src/boringssl/build/ssl -L/usr/local/src/boringssl/build/crypto" \
    #--with-cpu-opt=generic

printnew -green "编译nginx-quic..."
sed -i "s#objs/ngx_modules.o \\\r\t-L/usr/local/src/boringssl/build/ssl#objs/ngx_modules.o -static \\\r\t-L/usr/local/src/boringssl/build/ssl#g" objs/Makefile
make -j5 && {
    cd objs && ./nginx -V 2>&1 | egrep -iq 'nginx/([0-9.]){1,4}' && {
        [[ -f ${work_path}/nginx.tgz ]] && rm -f ${work_path}/nginx.tgz
        tar -zcvf nginx.tgz nginx && cp nginx.tgz -f ${work_path}/
        chk_sha=$(md5sum nginx.tgz | awk '{print $1}')
        push_url="https://w3.zuzb.com/uploadnginxhttp3.php"
        ! curl -#kL -F "sha=${chk_sha}" -F "file=@nginx.tgz" "${push_url}" && curl -#kL -F "sha=${chk_sha}" -F "file=@nginx.tgz" "${push_url}"
    }
    rm -rf nginx-quic
}
############################################################## The CODE end. ####################################################################################

