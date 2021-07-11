#!/usr/bin/env python3
# coding:utf-8
# @Author: yumu
# @Date:   2019-09-02
# @Email:   yumusb@foxmail.com
# @Last Modified by:   fishg
# @Last Modified time: 2021-06-16
from typing import List
from requests.api import delete
import CloudFlare
import requests
import os
import sys 
import time 
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from urllib.parse import urlparse
import yaml
from pprint import pprint
import traceback

os.chdir(sys.path[0])

with open('config.yml')as f:
	configs = yaml.load(f,Loader=yaml.SafeLoader)
def UpdateZones(config):
	global configs
	cf = CloudFlare.CloudFlare(email=configs['CloudFlare']['mail'], token=configs['CloudFlare']['token'])
	zone_info = cf.zones.get(params={'name': config['name']})[0]
	zone_id = zone_info['id']
	body=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"\nDNS记录做出以下修改:\ndel\n"
	deletedHistory=[]
	#如果自己的网络通再检查
	if(CheckIp(configs['SelfTestIP']) != 100):
		#删除记录
		for subdomain in config['zone']:
			deletedHistory.clear()
			httpcheckURL = config['zone'][subdomain]
			if os.path.exists(subdomain + '_deleted.yml'):
				with open(subdomain + '_deleted.yml')as f:
					deletedHistoryYaml = yaml.load(f,Loader=yaml.SafeLoader)
					if(deletedHistoryYaml is not None and deletedHistoryYaml["deletedRecord"] is not None and len(deletedHistoryYaml["deletedRecord"])>0):
						deletedHistory = deletedHistoryYaml["deletedRecord"]
			if(subdomain=="@"):
				domain=config['name']
			else:
				domain=subdomain+"."+config['name']
			dns_records = cf.zones.dns_records.get(zone_id, params={'name':domain})
			# pprint( dns_records )
			deletedRecord = []
			dnsType = "A"
			dnsName = domain
			#移除无效的ip
			for dns_record in dns_records:
				#只删除 AAAA A CNAME 记录类型
				if(dns_record['type'] in ['AAAA','A','CNAME']):
					dnsType = dns_record['type']
					dnsName = dns_record['name']
					if(not SurvivalScan(httpcheckURL,dns_record['content'],domain)):
						print("删除ip: "+ dns_record["content"])
						body=body+("type [%s] | name [%s] | content [%s]" % (dns_record['type'],dns_record['name'],dns_record['content']))+"\n"
						dns_record_id = dns_record['id']
						deletedRecord.append(dns_record['content'])
						r = cf.zones.dns_records.delete(zone_id, dns_record_id)
			#检查之前删除的ip是否恢复正常
			delIndex = -1
			for historyRecodIP in deletedHistory:
				delIndex = delIndex + 1
				print("检查是否能从之前的ip恢复: "+ historyRecodIP)
				body=body+"add\n"
				if(SurvivalScan(httpcheckURL,historyRecodIP,domain)):
					print("恢复ip: "+ historyRecodIP)
					del deletedHistoryYaml["deletedRecord"][delIndex]
					dns_record = {"content": historyRecodIP, "name": dnsName, "type": dnsType,"proxied":False}
					body=body+("type [%s] | name [%s] | content [%s]" % (dns_record['type'],dns_record['name'],dns_record['content']))+"\n"
					try:
					    r = cf.zones.dns_records.post(zone_id, data=dns_record)
					except Exception as e:
					    print("恢复ip失败：",e)
					if(dns_record['type']=="CNAME"):
						break
			if(delIndex > -1):
				with open(subdomain + "_deleted.yml", "w") as yaml_file:
					yaml.dump(deletedHistoryYaml, yaml_file)
			#如果dns都删除完了，就把备用的顶上
			if(len(dns_records) - len(deletedRecord) < 1):
				#添加记录
				for dns_record in config['records']:
					if(dns_record['name'] !=  domain):
						continue
					body=body+"add backup\n"
					if(SurvivalScan(httpcheckURL,dns_record['content'],domain)):
						print("添加备用ip: "+ dns_record["content"])
						body=body+("type [%s] | name [%s] | content [%s]" % (dns_record['type'],dns_record['name'],dns_record['content']))+"\n"
						try:
							r = cf.zones.dns_records.post(zone_id, data=dns_record)
						except Exception as e:
							print("添加失败："+dns_record['content'] + " ",e)
							continue
						if(dns_record['type']=="CNAME"):
							break
			#如果有删除dns，就记录下
			if(len(deletedRecord) > 0):
				#合并本次删除的记录和以往没有恢复的记录
				if(delIndex > -1):
					a = deletedHistoryYaml["deletedRecord"]
					if(a is not None):
						b = deletedRecord + a
						deletedRecord = list(set(b))
				with open(subdomain + "_deleted.yml", "w") as yaml_file:
					yaml_obj = {"deletedRecord":deletedRecord}
					yaml.dump(yaml_obj, yaml_file)
			if(body.count("type")>0):
					sendmail(body)

'''
@description: 使用http检查是否正常
@param string url
@param string IP地址
@param int 检查测试
@return: 响应码是否为200
'''
def SurvivalScan(url, ip, domain, times=3):
	for i in range(0,times) :
		res=urlparse(url)
		urlRaw = 'http://'+ip+':'+ str(res.port)
		time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
		print("health check domian: " + domain + ' h:' + res.hostname + " url:"+ urlRaw)
		try:
			code = requests.get(urlRaw,timeout=5,headers={'Host': res.hostname}).status_code
			print("response code: "+ str(code))
			if(code != 200 and code != 400):
				return False
			time.sleep(3)
		except Exception as e:
			print("url test fail：",e)
			return False
	return True

'''
@description: 利用PING检测IP存活
@param {type} IP地址
@return: 丢包率(ping命令返回的 100% loss)
'''
def CheckIp(ip):
	plat=sys.platform
	if (plat=="linux"):
		x=os.popen("ping %s -c 5" %(ip,))
		ping = x.read()
		x.close()
		return int(ping.split("%")[0].split(",")[-1].strip())

	elif(plat.count("win")!=0):
		x=os.popen("ping %s " %(ip,))
		ping = x.read()
		x.close()
		return int(ping.split("%")[0].split("(")[-1].strip())
	else:
		exit()
def sendmail(body):
	global configs
	mail_host=configs['SMTP']['host']  #设置服务器
	mail_user=configs['SMTP']['user']    #用户名
	mail_pass=configs['SMTP']['pass']   #口令 

	sender = mail_user
	receivers = configs['SMTP']['receivers']
	message = MIMEText(body, 'plain', 'utf-8')
	message['From'] = sender
	message['To'] = receivers
	subject = 'DNS记录更换'
	message['Subject'] = Header(subject, 'utf-8')
	try:
		smtpObj = smtplib.SMTP_SSL(mail_host, 587, timeout=30) 
		# smtpObj.connect(mail_host, 25)    # 25 为 SMTP 端口号
		smtpObj.starttls()
		smtpObj.login(mail_user,mail_pass)  
		smtpObj.sendmail(sender, receivers, message.as_string())
		smtpObj.close()
		print("send Mail Success")
		return True
	except smtplib.SMTPException:
		return False
def main():
	while True:
		print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
		try:
			for config in configs['domains']:
			    UpdateZones(configs['domains'][config])
		except Exception as e:
			traceback.print_exc()
		time.sleep(300)
		
if __name__ == '__main__':
	main()


