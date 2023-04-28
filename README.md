# 常见的未授权漏洞检测

项目包含1 、FTP 未授权访问（21）  
2 、LDAP 未授权访问（389）  
3 、Rsync 未授权访问（873）  
4 、ZooKeeper 未授权访问（2181）  
5 、Docker 未授权访问（2375）  
6 、Docker Registry未授权（5000）  
7 、Kibana 未授权访问（5601）  
8 、VNC 未授权访问（5900、5901）  
9 、CouchDB 未授权访问（5984）  
10 、Apache Spark 未授权访问（6066、8081、8082）  
11 、Redis 未授权访问（6379）  
12 、Weblogic 未授权访问（7001）  
13 、HadoopYARN 未授权访问（8088）  
14 、JBoss 未授权访问（8080）  
15 、Jenkins 未授权访问（8080）  
16 、Kubernetes Api Server 未授权（8080、10250）  
17 、Active MQ 未授权访问（8161）  
18 、Jupyter Notebook 未授权访问（8888）  
19 、Elasticsearch 未授权访问（9200、9300）  
20 、Zabbix 未授权访问（10051）  
21 、Memcached 未授权访问（11211）  
22 、RabbitMQ 未授权访问（15672、15692、25672）  
23 、MongoDB 未授权访问（27017）  
24 、NFS 未授权访问（2049、20048）  
25 、Dubbo 未授权访问（28096）  
26 、Druid 未授权访问  
27 、Solr 未授权访问  
28 、SpringBoot Actuator 未授权访问  
29 、SwaggerUI未授权访问漏洞  
30 、Harbor未授权添加管理员漏洞  
31 、Windows ipc共享未授权访问漏洞  
32 、宝塔phpmyadmin未授权访问  
33 、WordPress未授权访问漏洞  
34 、Atlassian Crowd 未授权访问  
35 、PHP-FPM Fastcgi未授权访问漏洞  
36 、uWSGI未授权访问漏洞  
37 、Kong未授权访问漏洞  
38 、ThinkAdminV6未授权访问漏洞  
# 代码规范，可以自己添加其他漏洞检测
# Usage
pip install -r requestments.txt  
python3 main.py
# Screenshot
![存在漏洞](https://user-images.githubusercontent.com/126586204/235194877-b84ffd82-469b-4016-b924-672bc671d652.PNG)

# 免责声明
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。 在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。 如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
