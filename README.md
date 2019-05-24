# Nginx 安装脚本


注意: 

  脚本目前理论支持CentOS6,7和Redhat6,7, 由于Redhat是商业系统, 所以我仅在CentOS6,7上完美测试成功.因此建议不要用于生产环境. 


安装方法1:

    git clone https://github.com/viagram/Nginx.git && sh Nginx/install.sh

安装方法2:

    curl -skL https://codeload.github.com/viagram/Nginx/zip/master -o Nginx-master.zip && unzip Nginx-master.zip && rm -f Nginx-master.zip && sh Nginx-master/install.sh

按提示操作, 基本按几下回车键即可.
