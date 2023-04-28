import ftplib
import socket
import sys

import memcache
import pymongo
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton

class SecurityChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('常见端口未授权漏洞检测系统                                                                                                      designd by xkllz date:2023-04-28')

        # 创建标签和输入框
        self.url_label = QLabel('IP:', self)
        self.url_label.move(20, 20)
        self.url_input = QLineEdit(self)
        self.url_input.move(80, 20)

        # 创建按钮
        self.ftp_button = QPushButton('ftp', self)
        self.ftp_button.move(20, 50)
        self.ftp_button.clicked.connect(self.check_ftp)

        self.vnc_button = QPushButton('vnc', self)
        self.vnc_button.move(20, 100)
        self.vnc_button.clicked.connect(self.check_vnc)

        self.solr_button = QPushButton('solr', self)
        self.solr_button.move(20, 150)
        self.solr_button.clicked.connect(self.check_solr)

        self.weblogic_button = QPushButton('weblogic', self)
        self.weblogic_button.move(20, 200)
        self.weblogic_button.clicked.connect(self.check_weblogic)

        self.jboss_button = QPushButton('JBoss', self)
        self.jboss_button.move(120, 50)
        self.jboss_button.clicked.connect(self.check_jboss)

        self.es_button = QPushButton('elasticsearch', self)
        self.es_button.move(120, 100)
        self.es_button.clicked.connect(self.check_elasticsearch)

        self.kubernetes_button = QPushButton('kubernetes', self)
        self.kubernetes_button.move(120, 150)
        self.kubernetes_button.clicked.connect(self.check_kubernetes_api_server)

        self.dockerreg_button = QPushButton('docker registry', self)
        self.dockerreg_button.move(120, 200)
        self.dockerreg_button.clicked.connect(self.check_docker_registry)

        self.ldap_button = QPushButton('LDAP', self)
        self.ldap_button.move(220, 50)
        self.ldap_button.clicked.connect(self.check_ldap)

        self.jenkins_button = QPushButton('jenkins', self)
        self.jenkins_button.move(220, 100)
        self.jenkins_button.clicked.connect(self.check_jenkins)

        self.couchdb_button = QPushButton('couchdb', self)
        self.couchdb_button.move(220, 150)
        self.couchdb_button.clicked.connect(self.check_couchdb)

        self.hadoopyarn_button = QPushButton('hadoopYARN', self)
        self.hadoopyarn_button.move(220, 200)
        self.hadoopyarn_button.clicked.connect(self.check_hadoop_yarn)

        self.redis_button = QPushButton('Redis', self)
        self.redis_button.move(320, 50)
        self.redis_button.clicked.connect(self.check_redis)

        self.kibana_button = QPushButton('kibana', self)
        self.kibana_button.move(320, 100)
        self.kibana_button.clicked.connect(self.check_kibana)

        self.spat_button = QPushButton('spring actuator', self)
        self.spat_button.move(320, 150)
        self.spat_button.clicked.connect(self.check_spring_boot_actuator)

        self.wordpress_button = QPushButton('wordpress', self)
        self.wordpress_button.move(320, 200)
        self.wordpress_button.clicked.connect(self.check_wordpress)

        self.nfs_button = QPushButton('Nfs', self)
        self.nfs_button.move(420, 50)
        self.nfs_button.clicked.connect(self.check_nfs)

        self.ipc_button = QPushButton('ipc', self)
        self.ipc_button.move(420, 100)
        self.ipc_button.clicked.connect(self.check_ipc)

        self.uwsgi_button = QPushButton('uwsgi', self)
        self.uwsgi_button.move(420, 150)
        self.uwsgi_button.clicked.connect(self.check_uwsgi)

        self.harbor_button = QPushButton('harbor', self)
        self.harbor_button.move(420, 200)
        self.harbor_button.clicked.connect(self.check_harbor)

        self.zookeeper_button = QPushButton('zookeeper', self)
        self.zookeeper_button.move(520, 50)
        self.zookeeper_button.clicked.connect(self.check_zookeeper)

        self.druid_button = QPushButton('druid', self)
        self.druid_button.move(520, 100)
        self.druid_button.clicked.connect(self.check_druid)

        self.tkad6_button = QPushButton('thinkadmin_v6', self)
        self.tkad6_button.move(520, 150)
        self.tkad6_button.clicked.connect(self.check_thinkadmin_v6)

        self.activemq_button = QPushButton('activemq', self)
        self.activemq_button.move(520, 200)
        self.activemq_button.clicked.connect(self.check_activemq)

        self.swaggerui_button = QPushButton('swaggerui', self)
        self.swaggerui_button.move(620, 50)
        self.swaggerui_button.clicked.connect(self.check_swaggerui)

        self.rabbitmq_button = QPushButton('rabbitmq', self)
        self.rabbitmq_button.move(620, 100)
        self.rabbitmq_button.clicked.connect(self.check_rabbitmq)

        self.phpfpm_button = QPushButton('php_fpm_fastcgi', self)
        self.phpfpm_button.move(620, 150)
        self.phpfpm_button.clicked.connect(self.check_php_fpm_fastcgi)

        self.atlc_button = QPushButton('atlassianc', self)
        self.atlc_button.move(620, 200)
        self.atlc_button.clicked.connect(self.check_atlassian_crowd)

        self.docker_button = QPushButton('docker', self)
        self.docker_button.move(720, 50)
        self.docker_button.clicked.connect(self.check_docker)

        self.dubbo_button = QPushButton('dubbo', self)
        self.dubbo_button.move(720, 100)
        self.dubbo_button.clicked.connect(self.check_dubbo)

        self.mongodb_button = QPushButton('mongodb', self)
        self.mongodb_button.move(720, 150)
        self.mongodb_button.clicked.connect(self.check_mongodb)

        self.zabbix_button = QPushButton('zabbix', self)
        self.zabbix_button.move(720, 200)
        self.zabbix_button.clicked.connect(self.check_zabbix)

        self.memcached_button = QPushButton('memcached', self)
        self.memcached_button.move(820, 50)
        self.memcached_button.clicked.connect(self.check_memcached)

        self.btphp_button = QPushButton('bt_phpmyadmin', self)
        self.btphp_button.move(820, 100)
        self.btphp_button.clicked.connect(self.check_bt_phpmyadmin)

        self.jupyter_button = QPushButton('jupyter', self)
        self.jupyter_button.move(820, 150)
        self.jupyter_button.clicked.connect(self.check_jupyter_notebook)

        self.rsync_button = QPushButton('rsync', self)
        self.rsync_button.move(920, 50)
        self.rsync_button.clicked.connect(self.check_rsync)

        self.apsk_button = QPushButton('apache_spark', self)
        self.apsk_button.move(920, 100)
        self.apsk_button.clicked.connect(self.check_apache_spark)

        self.kong_button = QPushButton('kong', self)
        self.kong_button.move(920, 150)
        self.kong_button.clicked.connect(self.check_kong)

        # 创建结果标签
        self.result_label = QLabel('检测结果..........', self)
        self.result_label.move(20, 300)
        self.result_label.setFixedHeight(60) # 设置固定高度
        self.result_label.setFixedWidth(500)
        # 将结果标签的背景颜色设置为红色
        self.result_label.setStyleSheet('background-color: white; border: 1px solid black')
        # self.result_label.setWordWrap(True) # 开启自动换行

        # 设置窗口大小和显示
        self.setGeometry(600, 600, 1000, 400)
        self.show()

    def check_jboss(self):
        url = self.url_input.text()

        # 检查 JBoss 是否存在未授权访问漏洞
        jboss_url = url + '/jmx-console/'
        jboss_response = requests.get(jboss_url)
        if 'jboss' in jboss_response.headers.get('Server', '') and 'Welcome to JBossAS' in jboss_response.text:
            jboss_result = '存在jboss未授权访问漏洞\n'
        else:
            jboss_result = '不存在jboss未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(jboss_result)

    def check_ldap(self):
        url = self.url_input.text()

        # 检查 LDAP 是否存在未授权访问漏洞
        ldap_url = url + ':389'
        ldap_response = requests.get(ldap_url)
        if 'OpenLDAP' in ldap_response.headers.get('Server', '') and '80090308' in ldap_response.text:
            ldap_result = '存在ldap未授权访问漏洞\n'
        else:
            ldap_result = '不存在ldap未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(ldap_result)

    def check_redis(self):
        url = self.url_input.text()

        # 检查 Redis 是否存在未授权访问漏洞
        redis_url = url + ':6379/info'
        redis_response = requests.get(redis_url, allow_redirects=False)
        if redis_response.status_code == 200 and 'redis_version' in redis_response.text:
            redis_result = '存在redis未授权访问漏洞\n'
        else:
            redis_result = '不存在redis未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(redis_result)

    def check_nfs(self):
        ip = self.url_input.text()

        # 检查 NFS 是否存在未授权访问漏洞
        try:
            nfs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            nfs_socket.settimeout(3)
            nfs_socket.connect((ip, 2049))
            nfs_socket.sendall(b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            response = nfs_socket.recv(1024)
            if b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x02\x00\x00\x00\x01' in response:
                nfs_result = '存在nfs未授权访问漏洞\n'
            else:
                nfs_result = '不存在nfs未授权访问漏洞\n'
        except:
            nfs_result = '无法连接到该 IP\n'

        # 显示结果
        self.result_label.setText(nfs_result)

    def check_ftp(self):
        ip = self.url_input.text()

        # 检查 FTP 是否存在未授权访问漏洞
        try:
            ftp = ftplib.FTP(ip)
            ftp.login()
            ftp.cwd('/')
            ftp.quit()
            ftp_result = '存在ftp未授权访问漏洞\n'
        except:
            ftp_result = '不存在ftp未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(ftp_result)

    def check_zookeeper(self):
        url = self.url_input.text()
        # 检查 Zookeeper 是否存在未授权访问漏洞
        zookeeper_url = url + ':2181'
        try:
            zookeeper_response = requests.get(zookeeper_url, timeout=5)
            if 'Zookeeper' in zookeeper_response.headers.get('Server',
                                                             '') and zookeeper_response.status_code == 200:
                zookeeper_result = '存在zookeeper未授权访问漏洞\n'
            else:
                zookeeper_result = '不存在zookeeper未授权访问漏洞\n'
        except:
            zookeeper_result = '无法连接到 Zookeeper 服务\n'
        # 显示结果
        self.result_label.setText(zookeeper_result)

    # 检查 VNC 是否存在未授权访问漏洞
    def check_vnc(self):
        ip = self.url_input.text()
        vnc_url = f'vnc://{ip}'
        try:
            tigerVNC_response = requests.get(vnc_url, timeout=5)
            if "RFB 003.008\n" in tigerVNC_response.content.decode('utf-8'):
                vnc_result = '存在vnc未授权访问漏洞\n'
            else:
                vnc_result = '不存在vnc未授权访问漏洞\n'
        except:
            vnc_result = '不存在vnc未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(vnc_result)

    # 检查 Elasticsearch 是否存在未授权访问漏洞
    def check_elasticsearch(self):
        ip = self.url_input.text()
        url = f'http://{ip}:9200/_cat'
        try:
            response = requests.get(url, timeout=5)
            if '/_cat/master' in response.text:
                elasticsearch_result = '存在elasticsearch未授权访问漏洞\n'
            else:
                elasticsearch_result = '不存在elasticsearch未授权访问漏洞\n'
        except:
            elasticsearch_result = '不存在elasticsearch未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(elasticsearch_result)

    # 检查 Jenkins 是否存在未授权访问漏洞
    def check_jenkins(self):
        ip = self.url_input.text()
        jenkins_url = f'http://{ip}:8080'
        try:
            response = requests.get(jenkins_url, timeout=5)
            if 'jenkins' in response.headers.get('X-Jenkins', '') and 'Dashboard [Jenkins]' in response.text:
                jenkins_result = '存在jenkins未授权访问漏洞\n'
            else:
                jenkins_result = '不存在jenkins未授权访问漏洞\n'
        except:
            jenkins_result = '不存在jenkins未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(jenkins_result)

    # 检查 Kibana 是否存在未授权访问漏洞
    def check_kibana(self):
        ip = self.url_input.text()
        kibana_url = f'http://{ip}:5601'
        try:
            response = requests.get(kibana_url, timeout=5)
            if 'kbn-name="kibana"' in response.text:
                kibana_result = '存在kibana未授权访问漏洞\n'
            else:
                kibana_result = '不存在kibana未授权访问漏洞\n'
        except:
            kibana_result = '不存在kibana未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(kibana_result)

    # 检查 IPC 是否存在未授权访问漏洞
    def check_ipc(self):
        ip = self.url_input.text()
        ipc_url = f'http://{ip}:445'
        try:
            response = requests.get(ipc_url, timeout=5)
            if 'IPC Service' in response.text:
                ipc_result = '存在ipc未授权访问漏洞\n'
            else:
                ipc_result = '不存在ipc未授权访问漏洞\n'
        except:
            ipc_result = '不存在ipc未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(ipc_result)

    # 检查 Druid 是否存在未授权访问漏洞
    def check_druid(self):
        ip = self.url_input.text()
        druid_url = f'http://{ip}:8888/druid/index.html'
        try:
            response = requests.get(druid_url, timeout=5)
            if 'Druid Console' in response.text:
                druid_result = '存在druid未授权访问漏洞\n'
            else:
                druid_result = '不存在druid未授权访问漏洞\n'
        except:
            druid_result = '不存在druid未授权访问漏洞\n'

            # 显示结果
        self.result_label.setText(druid_result)
    def check_swaggerui(self):
        url = self.url_input.text()
        # 检查 SwaggerUI 是否存在未授权访问漏洞
        swaggerui_url = url + '/swagger-ui.html'
        try:
            swaggerui_response = requests.get(swaggerui_url, timeout=5)
            if 'Swagger' in swaggerui_response.text:
                swaggerui_result = '存在swaggerui未授权访问漏洞\n'
            else:
                swaggerui_result = '不存在swaggerui未授权访问漏洞\n'
        except:
            swaggerui_result = '无法连接到 SwaggerUI 应用程序\n'
        # 显示结果
        self.result_label.setText(swaggerui_result)
    def check_docker(self):
        url = self.url_input.text()
        # 检查 Docker 是否存在未授权访问漏洞
        docker_url = 'http://' + url + ':2375/version'
        try:
            docker_response = requests.get(docker_url, timeout=5)
            if docker_response.status_code == 200 and 'ApiVersion' in docker_response.json():
                docker_result = '存在docker未授权访问漏洞\n'
            else:
                docker_result = '不存在docker未授权访问漏洞\n'
        except:
            docker_result = '无法连接到 Docker 守护进程\n'
        # 显示结果
        self.result_label.setText(docker_result)

    # 检查 RabbitMQ 是否存在未授权访问漏洞
    def check_rabbitmq(self):
        ip = self.url_input.text()
        rabbitmq_url = f'http://{ip}:15672/'

        try:
            response = requests.get(rabbitmq_url, timeout=5)
            if 'RabbitMQ Management' in response.text and 'overview-module' in response.text:
                rabbitmq_result = '存在rabbitmq未授权访问漏洞\n'
            else:
                rabbitmq_result = '不存在rabbitmq未授权访问漏洞\n'
        except:
            rabbitmq_result = '不存在rabbitmq未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(rabbitmq_result)

    # 检查 Memcached 是否存在未授权访问漏洞
    def check_memcached(self):
        ip = self.url_input.text()

        try:
            memcached_client = memcache.Client([ip], timeout=5)
            stats = memcached_client.get_stats()
            if len(stats) > 0:
                memcached_result = '存在memcached未授权访问漏洞\n'
            else:
                memcached_result = '不存在memcached未授权访问漏洞\n'
        except:
            memcached_result = '不存在memcached未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(memcached_result)

    # 检查 Dubbo 是否存在未授权访问漏洞
    def check_dubbo(self):
        ip = self.url_input.text()
        url = f'http://{ip}:8080/'
        try:
            response = requests.get(url, timeout=5)
            if 'dubbo' in response.headers and 'Welcome to the Dubbo' in response.text:
                dubbo_result = '存在dubbo未授权访问漏洞\n'
            else:
                dubbo_result = '不存在dubbo未授权访问漏洞\n'
        except:
            dubbo_result = '不存在dubbo未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(dubbo_result)

    # 检查宝塔phpmyadmin是否存在未授权访问漏洞
    def check_bt_phpmyadmin(self):
        ip = self.url_input.text()
        phpmyadmin_url = f'http://{ip}/phpmyadmin/'
        try:
            response = requests.get(phpmyadmin_url, timeout=5)
            if 'phpMyAdmin' in response.text:
                bt_phpmyadmin_result = '存在bt_phpmyadmin未授权访问漏洞\n'
            else:
                bt_phpmyadmin_result = '不存在bt_phpmyadmin未授权访问漏洞\n'
        except:
            bt_phpmyadmin_result = '不存在bt_phpmyadmin未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(bt_phpmyadmin_result)

    # 检查 Rsync 是否存在未授权访问漏洞
    def check_rsync(self):
        ip = self.url_input.text()
        rsync_url = f'rsync://{ip}'
        try:
            response = requests.get(rsync_url, timeout=5)
            if 'rsync' in response.headers.get('Server', '') and 'rsyncd.conf' in response.text:
                rsync_result = '存在rsync未授权访问漏洞\n'
            else:
                rsync_result = '不存在rsync未授权访问漏洞\n'
        except:
            rsync_result = '不存在rsync未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(rsync_result)

    # 检查 Solr 是否存在未授权访问漏洞
    def check_solr(self):
        ip = self.url_input.text()
        solr_url = f'http://{ip}:8983/solr/'
        try:
            response = requests.get(solr_url, timeout=5)
            if 'Apache Solr' in response.text:
                solr_result = '存在solr未授权访问漏洞\n'
            else:
                solr_result = '不存在solr未授权访问漏洞\n'

        except:
            solr_result = '不存在solr未授权访问漏洞\n'
            # 显示结果
        self.result_label.setText(solr_result)

    # 检查 Kubernetes Api Server 是否存在未授权访问漏洞
    def check_kubernetes_api_server(self):
        ip = self.url_input.text()
        api_server_url = f'https://{ip}:6443/api/'

        try:
            response = requests.get(api_server_url, verify=False, timeout=5)
            if 'Unauthorized' in response.text:
                kubernetes_api_server_result = '存在kubernetes_api_server未授权访问漏洞\n'
            else:
                kubernetes_api_server_result = '不存在kubernetes_api_server未授权访问漏洞\n'
        except:
            kubernetes_api_server_result = '不存在kubernetes_api_server未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(kubernetes_api_server_result)

    # 检查 CouchDB 是否存在未授权访问漏洞
    def check_couchdb(self):
        ip = self.url_input.text()
        couchdb_url = f'http://{ip}:5984/_utils/'

        try:
            response = requests.get(couchdb_url, timeout=5)
            if 'Welcome to CouchDB' in response.text:
                couchdb_result = '存在couchdb未授权访问漏洞\n'
            else:
                couchdb_result = '不存在couchdb未授权访问漏洞\n'
        except:
            couchdb_result = '不存在couchdb未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(couchdb_result)

    # 检查 Spring Boot Actuator 是否存在未授权访问漏洞
    def check_spring_boot_actuator(self):
        ip = self.url_input.text()
        actuator_url = f'http://{ip}:8080/actuator/'

        try:
            response = requests.get(actuator_url, timeout=5)
            if 'Hystrix' in response.text and 'health" : {' in response.text:
                spring_boot_actuator_result = '存在spring_boot_actuator未授权访问漏洞\n'
            else:
                spring_boot_actuator_result = '不存在spring_boot_actuator未授权访问漏洞\n'
        except:
            spring_boot_actuator_result = '不存在spring_boot_actuator未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(spring_boot_actuator_result)

    # 检查 uWSGI 是否存在未授权访问漏洞
    def check_uwsgi(self):
        ip = self.url_input.text()
        uwsgi_url = f'http://{ip}:1717/'

        try:
            response = requests.get(uwsgi_url, timeout=5)
            if 'uWSGI Status' in response.text:
                uwsgi_result = '存在uwsgi未授权访问漏洞\n'
            else:
                uwsgi_result = '不存在uwsgi未授权访问漏洞\n'
        except:
            uwsgi_result = '不存在uwsgi未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(uwsgi_result)

    # 检查 ThinkAdmin V6 是否存在未授权访问漏洞
    def check_thinkadmin_v6(self):
        ip = self.url_input.text()
        thinkadmin_url = f'http://{ip}/index/login.html'

        try:
            response = requests.get(thinkadmin_url, timeout=5)
            if 'ThinkAdmin' in response.text and 'logincheck' in response.text:
                thinkadmin_v6_result = '存在thinkadmin_v6未授权访问漏洞\n'
            else:
                thinkadmin_v6_result = '不存在thinkadmin_v6未授权访问漏洞\n'
        except:
            thinkadmin_v6_result = '不存在thinkadmin_v6未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(thinkadmin_v6_result)

    # 检查 PHP-FPM Fastcgi 是否存在未授权访问漏洞
    def check_php_fpm_fastcgi(self):
        ip = self.url_input.text()
        php_fpm_url = f'http://{ip}/php-fpm_status'

        try:
            response = requests.get(php_fpm_url, timeout=5)
            if 'pool:' in response.text and 'processes' in response.text:
                php_fpm_result = '存在php_fpm_fastcgi未授权访问漏洞\n'
            else:
                php_fpm_result = '不存在php_fpm_fastcgi未授权访问漏洞\n'
        except:
            php_fpm_result = '不存在php_fpm_fastcgi未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(php_fpm_result)

    # 检查 MongoDB 是否存在未授权访问漏洞
    def check_mongodb(self):
        ip = self.url_input.text()
        mongodb_url = f'mongodb://{ip}:27017/'

        try:
            client = pymongo.MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            if len(dbs) > 0:
                mongodb_result = '存在mongodb未授权访问漏洞\n'
            else:
                mongodb_result = '不存在mongodb未授权访问漏洞\n'
        except:
            mongodb_result = '不存在mongodb未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(mongodb_result)

    # 检查 Jupyter Notebook 是否存在未授权访问漏洞
    def check_jupyter_notebook(self):
        ip = self.url_input.text()
        notebook_url = f'http://{ip}:8888/'

        try:
            response = requests.get(notebook_url, timeout=5)
            if 'Jupyter Notebook' in response.text:
                jupyter_notebook_result = '存在jupyter_notebook未授权访问漏洞\n'
            else:
                jupyter_notebook_result = '不存在jupyter_notebook未授权访问漏洞\n'
        except:
            jupyter_notebook_result = '不存在jupyter_notebook未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(jupyter_notebook_result)

    # 检查 Apache Spark 是否存在未授权访问漏洞
    def check_apache_spark(self):
        ip = self.url_input.text()
        spark_url = f'http://{ip}:8080/'

        try:
            response = requests.get(spark_url, timeout=5)
            if 'Spark Master at' in response.text and 'Workers' in response.text:
                apache_spark_result = '存在apache_spark未授权访问漏洞\n'
            else:
                apache_spark_result = '不存在apache_spark未授权访问漏洞\n'
        except:
            apache_spark_result = '不存在apache_spark未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(apache_spark_result)

    # 检查 WebLogic 是否存在未授权访问漏洞
    def check_weblogic(self):
        ip = self.url_input.text()
        weblogic_url = f'http://{ip}:7001/console/login/LoginForm.jsp'

        try:
            response = requests.get(weblogic_url, timeout=5)
            if 'Oracle WebLogic Server' in response.text:
                weblogic_result = '存在weblogic未授权访问漏洞\n'
            else:
                weblogic_result = '不存在weblogic未授权访问漏洞\n'
        except:
            weblogic_result = '不存在weblogic未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(weblogic_result)

    # 检查 Docker Registry 是否存在未授权访问漏洞
    def check_docker_registry(self):
        ip = self.url_input.text()
        registry_url = f'http://{ip}/v2/_catalog'

        try:
            response = requests.get(registry_url, timeout=5)
            if 'repositories' in response.json():
                docker_registry_result = '存在docker_registry未授权访问漏洞\n'
            else:
                docker_registry_result = '不存在docker_registry未授权访问漏洞\n'
        except:
            docker_registry_result = '不存在docker_registry未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(docker_registry_result)

    # 检查 Hadoop YARN 是否存在未授权访问漏洞
    def check_hadoop_yarn(self):
        ip = self.url_input.text()
        yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'

        try:
            response = requests.get(yarn_url, timeout=5)
            if 'resourceManagerVersion' in response.json()['clusterInfo']:
                hadoop_yarn_result = '存在hadoop_yarn未授权访问漏洞\n'
            else:
                hadoop_yarn_result = '不存在hadoop_yarn未授权访问漏洞\n'
        except:
            hadoop_yarn_result = '不存在hadoop_yarn未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(hadoop_yarn_result)

    # 检查 Kong 是否存在未授权访问漏洞
    def check_kong(self):
        ip = self.url_input.text()
        kong_url = f'http://{ip}:8001/'

        try:
            response = requests.get(kong_url, timeout=5)
            if 'Welcome to Kong' in response.text:
                kong_result = '存在kong未授权访问漏洞\n'
            else:
                kong_result = '不存在kong未授权访问漏洞\n'
        except:
            kong_result = '不存在kong未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(kong_result)

    # 检查 WordPress 是否存在未授权访问漏洞
    def check_wordpress(self):
        ip = self.url_input.text()
        wordpress_url = f'http://{ip}/wp-login.php'

        try:
            response = requests.get(wordpress_url, timeout=5)
            if 'WordPress' in response.text:
                wordpress_result = '存在wordpress未授权访问漏洞\n'
            else:
                wordpress_result = '不存在wordpress未授权访问漏洞\n'
        except:
            wordpress_result = '不存在wordpress未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(wordpress_result)

    # 检查 Zabbix 是否存在未授权访问漏洞
    def check_zabbix(self):
        ip = self.url_input.text()
        zabbix_url = f'http://{ip}/zabbix/jsrpc.php'

        try:
            headers = {
                'Content-Type': 'application/json-rpc',
                'User-Agent': 'Mozilla/5.0'
            }
            data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
            response = requests.post(zabbix_url, headers=headers, data=data, timeout=5)
            if 'result' in response.json():
                zabbix_result = '存在zabbix未授权访问漏洞\n'
            else:
                zabbix_result = '不存在zabbix未授权访问漏洞\n'
        except:
            zabbix_result = '不存在zabbix未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(zabbix_result)

    # 检查 Active MQ 是否存在未授权访问漏洞
    def check_activemq(self):
        ip = self.url_input.text()
        activemq_url = f'http://{ip}:8161/admin/'

        try:
            response = requests.get(activemq_url, timeout=5)
            if 'Apache ActiveMQ' in response.text:
                activemq_result = '存在activemq未授权访问漏洞\n'
            else:
                activemq_result = '不存在activemq未授权访问漏洞\n'
        except:
            activemq_result = '不存在activemq未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(activemq_result)

    # 检查 Harbor 是否存在未授权访问漏洞
    def check_harbor(self):
        ip = self.url_input.text()
        harbor_url = f'http://{ip}/api/v2.0/statistics'

        try:
            response = requests.get(harbor_url, timeout=5)
            if 'total_projects' in response.json():
                harbor_result = '存在harbor未授权访问漏洞\n'
            else:
                harbor_result = '不存在harbor未授权访问漏洞\n'
        except:
            harbor_result = '不存在harbor未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(harbor_result)

    # 检查 Atlassian Crowd 是否存在未授权访问漏洞
    def check_atlassian_crowd(self):
        ip = self.url_input.text()
        crowd_url = f'http://{ip}:8095/crowd/'

        try:
            response = requests.get(crowd_url, timeout=5)
            if 'Atlassian Crowd' in response.text:
                atlassian_crowd_result = '存在atlassian_crowd未授权访问漏洞\n'
            else:
                atlassian_crowd_result = '不存在atlassian_crowd未授权访问漏洞\n'
        except:
            atlassian_crowd_result = '不存在atlassian_crowd未授权访问漏洞\n'

        # 显示结果
        self.result_label.setText(atlassian_crowd_result)
if __name__ == '__main__':
    app = QApplication(sys.argv)
    security_checker = SecurityChecker()
    sys.exit(app.exec_())
