import ftplib
import json
import socket
import sys
import memcache
import pymongo
import ldap3
import redis
import requests
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget,  QPushButton, QFileDialog


class SecurityChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(
            '常见端口未授权漏洞检测系统_V2                                  designed by xkllz date:2023-05-04')
        self.text = QtWidgets.QTextEdit(self)
        self.text.setPlaceholderText("请导入IP地址文件")
        self.text.move(20, 50)
        self.btn_import = QtWidgets.QPushButton("导入", self)
        self.btn_import.clicked.connect(self.import_file)
        self.btn_import.move(300, 50)
        # 创建保存结果按钮
        self.save_button = QPushButton('保存结果', self)
        self.save_button.move(300, 150)
        self.save_button.clicked.connect(self.save_results)
        # 创建按钮
        self.ftp_button = QPushButton('ftp', self)
        self.ftp_button.move(500, 50)
        self.ftp_button.clicked.connect(lambda: self.test_all_ips(self.check_ftp))

        self.vnc_button = QPushButton('vnc', self)
        self.vnc_button.move(500, 100)
        self.vnc_button.clicked.connect(lambda: self.test_all_ips(self.check_vnc))

        self.solr_button = QPushButton('solr', self)
        self.solr_button.move(500, 150)
        self.solr_button.clicked.connect(lambda: self.test_all_ips(self.check_solr))

        self.weblogic_button = QPushButton('weblogic', self)
        self.weblogic_button.move(500, 200)
        self.weblogic_button.clicked.connect(lambda: self.test_all_ips(self.check_weblogic))

        self.jboss_button = QPushButton('JBoss', self)
        self.jboss_button.move(500, 250)
        self.jboss_button.clicked.connect(lambda: self.test_all_ips(self.check_jboss))

        self.es_button = QPushButton('elasticsearch', self)
        self.es_button.move(500, 300)
        self.es_button.clicked.connect(lambda: self.test_all_ips(self.check_elasticsearch))

        self.kubernetes_button = QPushButton('kubernetes', self)
        self.kubernetes_button.move(500, 350)
        self.kubernetes_button.clicked.connect(lambda: self.test_all_ips(self.check_kubernetes_api_server))

        self.dockerreg_button = QPushButton('docker registry', self)
        self.dockerreg_button.move(500, 400)
        self.dockerreg_button.clicked.connect(lambda: self.test_all_ips(self.check_docker_registry))

        self.ldap_button = QPushButton('LDAP', self)
        self.ldap_button.move(500, 450)
        self.ldap_button.clicked.connect(lambda: self.test_all_ips(self.check_ldap))

        self.jenkins_button = QPushButton('jenkins', self)
        self.jenkins_button.move(500, 500)
        self.jenkins_button.clicked.connect(lambda: self.test_all_ips(self.check_jenkins))


        self.redis_button = QPushButton('Redis', self)
        self.redis_button.move(600, 50)
        self.redis_button.clicked.connect(lambda: self.test_all_ips(self.check_redis))

        self.kibana_button = QPushButton('kibana', self)
        self.kibana_button.move(600, 100)
        self.kibana_button.clicked.connect(lambda: self.test_all_ips(self.check_kibana))

        self.spat_button = QPushButton('spring actuator', self)
        self.spat_button.move(600, 150)
        self.spat_button.clicked.connect(lambda: self.test_all_ips(self.check_spring_boot_actuator))

        self.wordpress_button = QPushButton('wordpress', self)
        self.wordpress_button.move(600, 200)
        self.wordpress_button.clicked.connect(lambda: self.test_all_ips(self.check_wordpress))

        self.nfs_button = QPushButton('Nfs', self)
        self.nfs_button.move(600, 250)
        self.nfs_button.clicked.connect(lambda: self.test_all_ips(self.check_nfs))

        self.ipc_button = QPushButton('ipc', self)
        self.ipc_button.move(600, 300)
        self.ipc_button.clicked.connect(lambda: self.test_all_ips(self.check_ipc))

        self.uwsgi_button = QPushButton('uwsgi', self)
        self.uwsgi_button.move(600, 350)
        self.uwsgi_button.clicked.connect(lambda: self.test_all_ips(self.check_uwsgi))

        self.harbor_button = QPushButton('harbor', self)
        self.harbor_button.move(600, 400)
        self.harbor_button.clicked.connect(lambda: self.test_all_ips(self.check_harbor))

        self.zookeeper_button = QPushButton('zookeeper', self)
        self.zookeeper_button.move(600, 450)
        self.zookeeper_button.clicked.connect(lambda: self.test_all_ips(self.check_zookeeper))

        self.druid_button = QPushButton('druid', self)
        self.druid_button.move(600, 500)
        self.druid_button.clicked.connect(lambda: self.test_all_ips(self.check_druid))

        self.swaggerui_button = QPushButton('swaggerui', self)
        self.swaggerui_button.move(700, 50)
        self.swaggerui_button.clicked.connect(lambda: self.test_all_ips(self.check_swaggerui))

        self.rabbitmq_button = QPushButton('rabbitmq', self)
        self.rabbitmq_button.move(700, 100)
        self.rabbitmq_button.clicked.connect(lambda: self.test_all_ips(self.check_rabbitmq))

        self.phpfpm_button = QPushButton('php_fpm_fastcgi', self)
        self.phpfpm_button.move(700, 150)
        self.phpfpm_button.clicked.connect(lambda: self.test_all_ips(self.check_php_fpm_fastcgi))

        self.atlc_button = QPushButton('atlassianc', self)
        self.atlc_button.move(700, 200)
        self.atlc_button.clicked.connect(lambda: self.test_all_ips(self.check_atlassian_crowd))

        self.docker_button = QPushButton('docker', self)
        self.docker_button.move(700, 250)
        self.docker_button.clicked.connect(lambda: self.test_all_ips(self.check_docker))

        self.dubbo_button = QPushButton('dubbo', self)
        self.dubbo_button.move(700, 300)
        self.dubbo_button.clicked.connect(lambda: self.test_all_ips(self.check_dubbo))

        self.mongodb_button = QPushButton('mongodb', self)
        self.mongodb_button.move(700, 350)
        self.mongodb_button.clicked.connect(lambda: self.test_all_ips(self.check_mongodb))

        self.zabbix_button = QPushButton('zabbix', self)
        self.zabbix_button.move(700, 400)
        self.zabbix_button.clicked.connect(lambda: self.test_all_ips(self.check_zabbix))

        self.memcached_button = QPushButton('memcached', self)
        self.memcached_button.move(700, 450)
        self.memcached_button.clicked.connect(lambda: self.test_all_ips(self.check_memcached))

        self.btphp_button = QPushButton('bt_phpmyadmin', self)
        self.btphp_button.move(700, 500)
        self.btphp_button.clicked.connect(lambda: self.test_all_ips(self.check_bt_phpmyadmin))

        self.rsync_button = QPushButton('rsync', self)
        self.rsync_button.move(800, 50)
        self.rsync_button.clicked.connect(lambda: self.test_all_ips(self.check_rsync))

        self.apsk_button = QPushButton('apache_spark', self)
        self.apsk_button.move(800, 100)
        self.apsk_button.clicked.connect(lambda: self.test_all_ips(self.check_apache_spark))

        self.kong_button = QPushButton('kong', self)
        self.kong_button.move(800, 150)
        self.kong_button.clicked.connect(lambda: self.test_all_ips(self.check_kong))

        self.couchdb_button = QPushButton('couchdb', self)
        self.couchdb_button.move(800, 200)
        self.couchdb_button.clicked.connect(lambda: self.test_all_ips(self.check_couchdb))

        self.hadoopyarn_button = QPushButton('hadoopYARN', self)
        self.hadoopyarn_button.move(800, 250)
        self.hadoopyarn_button.clicked.connect(lambda: self.test_all_ips(self.check_hadoop_yarn))

        self.jupyter_button = QPushButton('jupyter', self)
        self.jupyter_button.move(800, 300)
        self.jupyter_button.clicked.connect(lambda: self.test_all_ips(self.check_jupyter_notebook))

        self.tkad6_button = QPushButton('thinkadmin_v6', self)
        self.tkad6_button.move(800, 350)
        self.tkad6_button.clicked.connect(lambda: self.test_all_ips(self.check_thinkadmin_v6))

        self.activemq_button = QPushButton('activemq', self)
        self.activemq_button.move(800, 400)
        self.activemq_button.clicked.connect(lambda: self.test_all_ips(self.check_activemq))

        self.result_label = QtWidgets.QPlainTextEdit(self)
        self.result_label.setReadOnly(True)
        self.result_label.setPlaceholderText("检测结果将显示在这里。")
        self.result_label.setGeometry(20, 350, 460, 200)

        self.setGeometry(600, 600, 1000, 600)
        self.show()

    # 导入IP地址文件并将其显示在文本框中
    def import_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "Text Files (*.txt)")

        if file_name:
            try:
                with open(file_name, "r") as f:
                    ip_list = f.read().splitlines()
                self.text.setPlainText("\n".join(ip_list))
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "警告", str(e))

    # 测试所有IP地址并将结果显示在结果标签中
    def test_all_ips(self, check_fn):
        ip_list = self.text.toPlainText().splitlines()
        if not ip_list:
            QtWidgets.QMessageBox.warning(self, "警告", "请导入IP地址文件或输入IP地址")
            return

        results = []
        for ip in ip_list:
            results.append(check_fn(ip))

        self.result_label.setPlainText("\n".join(results))
        # 保存结果到txt文件中

    def save_results(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "保存文件", "", "Text Files (*.txt)")

        if file_name:
            with open(file_name, "w") as f:
                f.write(self.result_label.toPlainText())
        # 检查 FTP 是否存在未授权访问漏洞

    def check_ftp(self, ip):
        try:
            ftp = ftplib.FTP(ip)
            ftp.login()
            ftp.cwd('/')
            ftp.quit()
            result = f"{ip}[+]存在FTP未授权访问漏洞"
        except:
            # 尝试常见弱密码
            weak_passwords = [('admin', 'admin'), ('anonymous', 'anonymous')]
            for user, pwd in weak_passwords:
                try:
                    ftp = ftplib.FTP(ip)
                    ftp.login(user, pwd)
                    ftp.cwd('/')
                    ftp.quit()
                    result = f"{ip}[+]存在FTP未授权访问漏洞（弱密码）"
                    return result
                except:
                    continue
            result = f"{ip} ftp无法连接"
        return result

    def check_jboss(self, ip):
        # 检查 JBoss 是否存在未授权访问漏洞
        endpoints = [
            f'http://{ip}:8080/jmx-console/',
            f'http://{ip}:8080/console/',
            f'http://{ip}:8080/invoker/JMXInvokerServlet'
        ]
        for url in endpoints:
            try:
                jboss_response = requests.get(url, timeout=5)
                if 'jboss' in jboss_response.headers.get('Server', '') and 'Welcome to JBossAS' in jboss_response.text:
                    result = f"{ip}[+]存在jboss未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在jboss未授权访问漏洞"
        return result

    # 检查 Solr 是否存在未授权访问漏洞
    def check_solr(self, ip):
        endpoints = [
            f'http://{ip}:8983/solr/',
            f'http://{ip}:8983/solr/admin/',
            f'http://{ip}:8983/solr/select'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'Apache Solr' in response.text:
                    result = f"{ip}[+]存在solr未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在solr未授权访问漏洞"
        return result
    # 检查 WebLogic 是否存在未授权访问漏洞
    def check_weblogic(self, ip):
        endpoints = [
            f'http://{ip}:7001/console/login/LoginForm.jsp',
            f'http://{ip}:7001/wls-wsat/CoordinatorPortType',
            f'http://{ip}:7001/console/css/console.css'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'Oracle WebLogic Server' in response.text:
                    result = f"{ip}[+]存在weblogic未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在weblogic未授权访问漏洞"
        return result
    def check_ldap(self, ip):

        try:
            server = ldap3.Server(f'ldap://{ip}:389')
            conn = ldap3.Connection(server)
            if conn.bind():
                result = f"{ip}[+]存在ldap未授权访问漏洞"
            else:
                result = f"{ip}不存在ldap未授权访问漏洞"
            conn.unbind()
        except:
            result = f"{ip}ldap无法连接"
        return result
    def check_redis(self, ip):
        # 检查 Redis 是否存在未授权访问漏洞
        redis_port = 6379
        try:
            # 尝试连接 Redis 服务
            r = redis.Redis(host=ip, port=redis_port, socket_timeout=3)
            # 尝试获取 Redis 信息
            info = r.info()
            result = f"{ip}[+]存在 redis 未授权访问漏洞"
        except redis.exceptions.AuthenticationError:
            result = f"{ip}不存在 redis 未授权访问漏洞"
        except redis.exceptions.ConnectionError:
            result = f"{ip}redis 无法连接"
        except Exception:
            result = f"{ip}检测时出现未知错误"
        # 显示结果
        return result
    def check_nfs(self, ip):
        # 检查 NFS 是否存在未授权访问漏洞
        try:
            nfs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            nfs_socket.settimeout(3)
            nfs_socket.connect((ip, 2049))
            nfs_socket.sendall(
                b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            response = nfs_socket.recv(1024)
            if b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x02\x00\x00\x00\x01' in response:
                result = f"{ip}[+]存在nfs未授权访问漏洞"
            else:
                result = f"{ip}不存在nfs未授权访问漏洞"
        except:
            result = f"nfs无法连接到该 {ip}"
        return result
    def check_zookeeper(self, ip):
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 2181))
            sock.send(b'stat')
            data = sock.recv(1024)
            if data:
                result = f"{ip}[+]存在zookeeper未授权访问漏洞"
            else:
                result = f"{ip}不存在zookeeper未授权访问漏洞"
            sock.close()
        except:
            result = f"{ip}无法连接到 Zookeeper 服务"
        return result
    def check_vnc(self, ip):
        try:
            import pyvnc  # 使用pyvnc库进行VNC连接尝试，需先安装该库
            client = pyvnc.VNC(ip, 5900)  # 假设默认端口5900，可根据实际调整
            client.connect()
            result = f"{ip}[+]存在vnc未授权访问漏洞"
            client.disconnect()
        except:
            result = f"{ip}vnc无法连接"
        return result
    # 检查 Elasticsearch 是否存在未授权访问漏洞
    def check_elasticsearch(self, ip):
        endpoints = [
            f'http://{ip}:9200/_cat',
            f'http://{ip}:9200/_nodes',
            f'http://{ip}:9200/_cluster/health'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    result = f"{ip}[+]存在elasticsearch未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在elasticsearch未授权访问漏洞"
        return result
    def check_jenkins(self, ip):
        jenkins_url = f'http://{ip}:8080'
        try:
            response = requests.get(jenkins_url, timeout=5)
            if 'jenkins' in response.headers.get('X-Jenkins', '') and 'Dashboard [Jenkins]' in response.text:
                # 增加判断是否能访问关键接口，如获取任务列表接口
                jobs_url = jenkins_url + "/api/json?tree=jobs[name]"
                jobs_response = requests.get(jobs_url, timeout=5)
                if jobs_response.status_code == 200:
                    result = f"{ip}[+]存在jenkins未授权访问漏洞"
                else:
                    result = f"{ip}不存在jenkins未授权访问漏洞"
            else:
                result = f"{ip}不存在jenkins未授权访问漏洞"
        except:
            result = f"{ip}jenkins无法连接"
        return result
    def check_kibana(self, ip):
        kibana_url = f'http://{ip}:5601'
        endpoints = [
            kibana_url,
            kibana_url + "/app/dashboards",
            kibana_url + "/api/saved_objects/_find?type=dashboard"
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    result = f"{ip}[+]存在kibana未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在kibana未授权访问漏洞"
        return result
    # 检查 IPC 是否存在未授权访问漏洞
    def check_ipc(self, ip):
        try:
            import smbclient
            try:
                smbclient.register_session(ip, username='', password='')
                result = f"{ip}[+]存在ipc未授权访问漏洞"
            except smbclient.AccessDenied:
                result = f"{ip}不存在ipc未授权访问漏洞"
            except:
                result = f"{ip}ipc无法连接"
        except ImportError:
            result = f"{ip}缺少 smbclient 库，无法检测 IPC"
        return result
    # 检查 Druid 是否存在未授权访问漏洞
    def check_druid(self, ip):
        endpoints = [
            f'http://{ip}:8888/druid/index.html',
            f'http://{ip}:8888/druid/console.html',
            f'http://{ip}:8888/druid/sql.html'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'Druid' in response.text:
                    result = f"{ip}[+]存在druid未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在druid未授权访问漏洞"
        return result
    def check_swaggerui(self, ip):
        endpoints = [
            ip + '/swagger-ui.html',
            ip + '/v2/api-docs',
            ip + '/swagger-resources'
        ]
        for url in endpoints:
            try:
                swaggerui_response = requests.get(url, timeout=5)
                if 'Swagger' in swaggerui_response.text:
                    result = f"{ip}[+]存在swaggerui未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在swaggerui未授权访问漏洞"
        return result
    def check_docker(self, ip):
        docker_url = 'http://' + ip + ':2375/version'
        try:
            response = requests.get(docker_url, timeout=5)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'ApiVersion' in data:
                        result = f"{ip}[+]存在docker未授权访问漏洞"
                    else:
                        result = f"{ip}不存在docker未授权访问漏洞"
                except json.JSONDecodeError:
                    result = f"{ip}不存在docker未授权访问漏洞"
            else:
                result = f"{ip}不存在docker未授权访问漏洞"
        except:
            result = f"{ip}无法连接到 Docker 守护进程"
        return result
    # 检查 RabbitMQ 是否存在未授权访问漏洞
    def check_rabbitmq(self, ip):
        endpoints = [
            f'http://{ip}:15672/',
            f'http://{ip}:15672/api/nodes',
            f'http://{ip}:15672/api/queues'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'RabbitMQ Management' in response.text and 'overview-module' in response.text:
                    result = f"{ip}[+]存在rabbitmq未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在rabbitmq未授权访问漏洞"
        return result
    def check_memcached(self, ip):
        try:
            memcached_client = memcache.Client([ip], timeout=5)
            # 尝试获取多个不同类型的统计信息来增加判断准确性
            stats = memcached_client.get_stats()
            settings = memcached_client.get_settings()
            if len(stats) > 0 or len(settings) > 0:
                result = f"{ip}[+]存在memcached未授权访问漏洞"
            else:
                result = f"{ip}不存在memcached未授权访问漏洞"
        except:
            result = f"{ip}memcached无法连接"
        return result
    # 检查 Dubbo 是否存在未授权访问漏洞
    def check_dubbo(self, ip):
        url = f'http://{ip}:8080/'
        try:
            response = requests.get(url, timeout=5)
            if 'dubbo' in response.headers and 'Welcome to the Dubbo' in response.text:
                result = f"{ip}[+]存在dubbo未授权访问漏洞"
            else:
                result = f"{ip}不存在dubbo未授权访问漏洞"
        except:
            result = f"{ip}dubbo无法连接"
        return result
    # 检查宝塔phpmyadmin是否存在未授权访问漏洞
    def check_bt_phpmyadmin(self, ip):
        endpoints = [
            f'http://{ip}/phpmyadmin/',
            f'http://{ip}/phpmyadmin/index.php',
            f'http://{ip}/phpmyadmin/config.inc.php'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'phpMyAdmin' in response.text:
                    result = f"{ip}[+]存在bt_phpmyadmin未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在bt_phpmyadmin未授权访问漏洞"
        return result
    def check_rsync(self, ip):
        try:
            import subprocess
            # 尝试使用rsync命令连接并获取信息
            command = f"rsync --list-only rsync://{ip}/"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            if process.returncode == 0:
                result = f"{ip}[+]存在rsync未授权访问漏洞"
            else:
                result = f"{ip}不存在rsync未授权访问漏洞"
        except:
            result = f"{ip}rsync无法连接"
        return result
    # 检查 Kubernetes Api Server 是否存在未授权访问漏洞
    def check_kubernetes_api_server(self, ip):
        api_server_url = f'https://{ip}:6443/api/'
        try:
            response = requests.get(api_server_url, timeout=5, verify=False)
            if response.status_code == 401:  # 更准确的判断未授权状态码
                result = f"{ip}[+]存在kubernetes_api_server未授权访问漏洞"
            elif response.status_code == 200:
                # 200可能表示已授权访问，也可能表示开放了未授权可访问的接口，进一步判断
                try:
                    data = response.json()
                    if "kind" in data:
                        result = f"{ip}[+]存在kubernetes_api_server未授权访问漏洞"
                    else:
                        result = f"{ip}不存在kubernetes_api_server未授权访问漏洞"
                except json.JSONDecodeError:
                    result = f"{ip}不存在kubernetes_api_server未授权访问漏洞"
            else:
                result = f"{ip}不存在kubernetes_api_server未授权访问漏洞"
        except:
            result = f"{ip}kubernetes无法连接"
        return result
    # 检查 CouchDB 是否存在未授权访问漏洞
    def check_couchdb(self, ip):
        endpoints = [
            f'http://{ip}:5984/_utils/',
            f'http://{ip}:5984/_all_dbs',
            f'http://{ip}:5984/_stats'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'Welcome to CouchDB' in response.text:
                    result = f"{ip}[+]存在couchdb未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在couchdb未授权访问漏洞"
        return result
    # 检查 Spring Boot Actuator 是否存在未授权访问漏洞
    def check_spring_boot_actuator(self, ip):
        endpoints = [
            f'http://{ip}:8080/actuator/',
            f'http://{ip}:8080/actuator/health',
            f'http://{ip}:8080/actuator/info',
            f'http://{ip}:8080/actuator/env'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    result = f"{ip}[+]存在spring_boot_actuator未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在spring_boot_actuator未授权访问漏洞"
        return result
    # 检查 uWSGI 是否存在未授权访问漏洞
    def check_uwsgi(self, ip):
        endpoints = [
            f'http://{ip}:1717/',
            f'http://{ip}:1717/admin',
            f'http://{ip}:1717/stats'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'uWSGI' in response.text:
                    result = f"{ip}[+]存在uwsgi未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在uwsgi未授权访问漏洞"
        return result
    # 检查 ThinkAdmin V6 是否存在未授权访问漏洞
    def check_thinkadmin_v6(self, ip):
        endpoints = [
            f'http://{ip}/index/login.html',
            f'http://{ip}/admin',
            f'http://{ip}/api'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'ThinkAdmin' in response.text:
                    result = f"{ip}[+]存在thinkadmin_v6未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在thinkadmin_v6未授权访问漏洞"
        return result
    # 检查 PHP-FPM Fastcgi 是否存在未授权访问漏洞
    def check_php_fpm_fastcgi(self, ip):
        endpoints = [
            f'http://{ip}/php-fpm_status',
            f'http://{ip}/status.php',
            f'http://{ip}/ping.php'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'PHP' in response.text and ('pool' in response.text or 'processes' in response.text):
                    result = f"{ip}[+]存在php_fpm_fastcgi未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在php_fpm_fastcgi未授权访问漏洞"
        return result
    # 检查 MongoDB 是否存在未授权访问漏洞
    def check_mongodb(self, ip):
        mongodb_url = f'mongodb://{ip}:27017/'
        try:
            client = pymongo.MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            if len(dbs) > 0:
                result = f"{ip}[+]存在mongodb未授权访问漏洞"
            else:
                result = f"{ip}不存在mongodb未授权访问漏洞"
        except:
            result = f"{ip}mongodb无法连接"
        return result
    # 检查 Jupyter Notebook 是否存在未授权访问漏洞
    def check_jupyter_notebook(self, ip):
        endpoints = [
            f'http://{ip}:8888/',
            f'http://{ip}:8888/api',
            f'http://{ip}:8888/user'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if 'Jupyter' in response.text:
                    result = f"{ip}[+]存在jupyter_notebook未授权访问漏洞"
                    return result
            except:
                continue
        result = f"{ip}不存在jupyter_notebook未授权访问漏洞"
        return result

    def check_apache_spark(self, ip):
        spark_url = f'http://{ip}:8080/'
        try:
            response = requests.get(spark_url, timeout=5)
            response.raise_for_status()
            if 'Spark Master at' in response.text and 'Workers' in response.text:
                result = f"{ip}[+]存在apache_spark未授权访问漏洞"
            else:
                result = f"{ip}不存在apache_spark未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}spark无法连接"
        except ValueError:
            result = f"{ip}spark响应内容解析错误"
        return result

    def check_docker_registry(self, ip):
        registry_url = f'http://{ip}/v2/_catalog'
        try:
            response = requests.get(registry_url, timeout=5)
            response.raise_for_status()
            json_data = response.json()
            if 'repositories' in json_data:
                result = f"{ip}[+]存在docker_registry未授权访问漏洞"
            else:
                result = f"{ip}不存在docker_registry未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}registry无法连接"
        except ValueError:
            result = f"{ip}registry响应内容不是有效的JSON格式"
        return result

    def check_hadoop_yarn(self, ip):
        yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'
        try:
            response = requests.get(yarn_url, timeout=5)
            response.raise_for_status()
            json_data = response.json()
            if 'resourceManagerVersion' in json_data.get('clusterInfo', {}):
                result = f"{ip}[+]存在hadoop_yarn未授权访问漏洞"
            else:
                result = f"{ip}不存在hadoop_yarn未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}yarn无法连接"
        except ValueError:
            result = f"{ip}yarn响应内容不是有效的JSON格式"
        return result

    def check_kong(self, ip):
        kong_url = f'http://{ip}:8001/'
        try:
            response = requests.get(kong_url, timeout=5)
            response.raise_for_status()
            if 'Welcome to Kong' in response.text:
                result = f"{ip}[+]存在kong未授权访问漏洞"
            else:
                result = f"{ip}不存在kong未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}kong无法连接"
        except ValueError:
            result = f"{ip}kong响应内容解析错误"
        return result

    def check_wordpress(self, ip):
        wordpress_url = f'http://{ip}/wp-login.php'
        try:
            response = requests.get(wordpress_url, timeout=5)
            response.raise_for_status()
            if 'WordPress' in response.text:
                result = f"{ip}[+]存在wordpress未授权访问漏洞"
            else:
                result = f"{ip}不存在wordpress未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}wordpress无法连接"
        except ValueError:
            result = f"{ip}wordpress响应内容解析错误"
        return result

    def check_zabbix(self, ip):
        zabbix_url = f'http://{ip}/zabbix/jsrpc.php'
        headers = {
            'Content-Type': 'application/json-rpc',
            'User-Agent': 'Mozilla/5.0'
        }
        data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
        try:
            response = requests.post(zabbix_url, headers=headers, data=data, timeout=5)
            response.raise_for_status()
            json_data = response.json()
            if 'result' in json_data:
                result = f"{ip}[+]存在zabbix未授权访问漏洞"
            else:
                result = f"{ip}不存在zabbix未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}zabbix无法连接"
        except ValueError:
            result = f"{ip}zabbix响应内容不是有效的JSON格式"
        return result

    def check_activemq(self, ip):
        activemq_url = f'http://{ip}:8161/admin/'
        try:
            response = requests.get(activemq_url, timeout=5)
            response.raise_for_status()
            if 'Apache ActiveMQ' in response.text:
                result = f"{ip}[+]存在activemq未授权访问漏洞"
            else:
                result = f"{ip}不存在activemq未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}activemq无法连接"
        except ValueError:
            result = f"{ip}activemq响应内容解析错误"
        return result

    def check_harbor(self, ip):
        harbor_url = f'http://{ip}/api/v2.0/statistics'
        try:
            response = requests.get(harbor_url, timeout=5)
            response.raise_for_status()
            json_data = response.json()
            if 'total_projects' in json_data:
                result = f"{ip}[+]存在harbor未授权访问漏洞"
            else:
                result = f"{ip}不存在harbor未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}harbor无法连接"
        except ValueError:
            result = f"{ip}harbor响应内容不是有效的JSON格式"
        return result

    def check_atlassian_crowd(self, ip):
        crowd_url = f'http://{ip}:8095/crowd/'
        try:
            response = requests.get(crowd_url, timeout=5)
            response.raise_for_status()
            if 'Atlassian Crowd' in response.text:
                result = f"{ip}[+]存在atlassian_crowd未授权访问漏洞"
            else:
                result = f"{ip}不存在atlassian_crowd未授权访问漏洞"
        except requests.RequestException:
            result = f"{ip}atlassian无法连接"
        except ValueError:
            result = f"{ip}atlassian响应内容解析错误"
        return result
if __name__ == '__main__':
    app = QApplication(sys.argv)
    security_checker = SecurityChecker()
    sys.exit(app.exec_())
