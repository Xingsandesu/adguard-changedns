#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import asyncio
import atexit
import sys
import os

import yaml
from adguardhome import AdGuardHome, AdGuardHomeError
from dns_client.adapters.requests import DNSClientSession
import logging
import time
import dns.resolver
from ping3 import ping, verbose_ping
import paramiko
import requests
from yaml import SafeLoader
from ikuai import iKuai
from openwrt import Openwrt

# 创建SSH连接对象
ssh_connect = paramiko.SSHClient()
ssh_connect.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
    # filename=log_path,
    # filemode='a',
)
logging.getLogger('dns_client').setLevel(logging.WARNING)

def is_host_online(hostname) -> bool:
    response = ping(hostname)
    return response

# 检查域名是否可以解析
def can_be_resolv(host):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [config['openwrt']['host']]
        resolver.resolve(host)
    except Exception:
        return False
    return True

# 检查URL是否可以通过HTTP访问
def can_be_http(url):
    try:
        # 发起请求，并指定请求头和SSL验证
        session = DNSClientSession(config['openwrt']['host'])
        session.head(url, timeout=5)
    except Exception:
        return False
    return True

# 检查网络状态
def check_network(ikuai):
    # 获取爱快WAN口信息
    wan_info = ikuai.get_ether_info_filter(config['ikuai']['check_wan'])
    if wan_info['errmsg'] != '线路检测成功':
        return f'爱快{config["ikuai"]["check_wan"]}线路检测失败'
    
    # 检查配置的域名是否可以解析
    for domain in config['openwrt']['check_dns_domain']:
        if not can_be_resolv(domain):
            return f'域名{domain} 解析失败'

    # 检查配置的URL是否可以访问
    for url in config['openwrt']['check_url']:
        if not can_be_http(url):
            return f'访问国外网站{url}失败'
    return ''

# 重启passwall服务
def passwall_restart():
    try:
        # 连接OpenWRT
        ssh_connect.connect(config['openwrt']['host'],
                            config['openwrt']['ssh_port'],
                            config['openwrt']['user'],
                            config['openwrt']['pwd'])
    except TimeoutError:
        logging.error('连接openwrt超时,请检查网络或openwrt配置')
    try:
        # 执行passwall重启命令
        ssh_connect.exec_command("uci set passwall.@global[0].enabled='0'")
        ssh_connect.exec_command('uci commit passwall')
        ssh_connect.exec_command('/sbin/reload_config')
        time.sleep(3)
        ssh_connect.exec_command("uci set passwall.@global[0].enabled='1'")
        ssh_connect.exec_command('uci commit passwall')
        ssh_connect.exec_command('/sbin/reload_config')
        logging.info(f'passwall重启完成')
        ssh_connect.close()
    except Exception as e:
        logging.error(f'passwall重启失败, 可能是适配问题,错误信息->{e}')
        ssh_connect.close()

# 异步设置AdGuardHome的上游DNS
async def set_adg_upstream(host, port, username, password, upstream_dns_list):
    try:
        async with AdGuardHome(host=host, port=port, username=username, password=password) as adguard:
            await adguard.request('dns_config', 'POST',
                                  json_data={"upstream_dns": upstream_dns_list})
    except AdGuardHomeError as e:
        error_message = str(e)
        if "(403, {'message': 'Forbidden'})" in error_message:
            logging.error("AdGuardHome认证错误: 访问被拒绝，请检查您的用户名和密码是否正确。")
            sys.exit(1)
        else:
            logging.error(f"AdGuardHomeError: {error_message}")
            sys.exit(1)
    except Exception as e:
        logging.error(f"发生未知错误: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', '-c', type=str, help='配置文件路径', default='config.yaml')
    args = vars(parser.parse_args())
    try:
        if not os.path.exists(args['config']):
            # 如果配置文件不存在，则创建一个示例配置文件
            sample_config = {
                'ikuai': {
                    'host': '爱快ip',
                    'port': 80,
                    'user': 'admin',
                    'pwd': '爱快密码',
                    'check_wan': 'wan2'
                },
                'openwrt': {
                    'host': 'openwrt ip',
                    'port': 80,
                    'user': 'root',
                    'pwd': 'openwrt密码',
                    'ssh_port': 22,
                    'check_dns_domain': [
                        'itdog.cn',
                        'ip.skk.moe'
                    ],
                    'check_url': [
                        'https://www.google.com/generate_204'
                    ],
                    'onfail_restart_passwall': True,
                    'restart_mode': 0,
                    'retry_count': 0,
                    'retry_interval': 10
                },
                'adguardhome': [
                    {
                        'host': 'adguard ip',
                        'port': 80,
                        'user': 'admin',
                        'pwd': 'adguard密码',
                        'normal_upstream_dns': [
                            'openwrt ip'
                        ],
                        'onfail_upstream_dns': [
                            '国内dns'
                        ]
                    }
                ],
                'check_interval': 30
            }
            with open(args['config'], 'w', encoding='utf-8') as f:
                yaml.dump(sample_config, f, allow_unicode=True)
            logging.info('示例配置文件已创建, 请修改后重新运行')
            sys.exit(0)
    
        # 加载配置文件
        with open(args['config'], 'r', encoding='utf-8') as f:
            config = yaml.load(f, SafeLoader)
        logging.info('配置文件已加载')
    except Exception as e:
        logging.error(f'加载配置文件时出错: {e}')
        sys.exit(1)

    prev_errmsg = '.'
    ikuai_logged = False
    ikuai = iKuai(host=config['ikuai']['host'], port=config['ikuai']['port'])
    atexit.register(ikuai.logout)

    while True:
        try:
            if not ikuai_logged:
                ikuai.login(config['ikuai']['user'], config['ikuai']['pwd'])
                ikuai_logged = True
            errmsg = check_network(ikuai)
            if not errmsg:
                if prev_errmsg:
                    for adg in config['adguardhome']:
                        asyncio.run(set_adg_upstream(adg['host'], adg['port'],
                                                     adg['user'], adg['pwd'],
                                                     adg['normal_upstream_dns']))
                        logging.info(
                            f'网络已恢复, 已经将adguardhome {adg["host"]}上游dns切换为{adg["normal_upstream_dns"]}')
                prev_errmsg = ''
            else:
                if errmsg != prev_errmsg:
                    prev_errmsg = errmsg

                    fail_count = 0
                    if config['openwrt']['retry_count'] > 0:
                        for i in range(config['openwrt']['retry_count']):
                            errmsg = check_network(ikuai)
                            logging.info(f'正在重新检测网络状态... {i + 1}/{config["openwrt"]["retry_count"]}')
                            if errmsg:
                                fail_count = fail_count + 1
                            else:
                                logging.info('网络恢已复, 取消重新检测')
                                break
                            time.sleep(config['openwrt']['retry_interval'])

                    if fail_count == config['openwrt']['retry_count']:
                        logging.info(f'重新检测全部失败')
                        for adg in config['adguardhome']:
                            asyncio.run(set_adg_upstream(adg['host'], adg['port'],
                                                         adg['user'], adg['pwd'],
                                                         adg['onfail_upstream_dns']))
                            logging.error(
                                f'错误信息->{errmsg}, 已经将adguardhome {adg["host"]}上游dns切换为{adg["onfail_upstream_dns"]}')
                        if config['openwrt']['onfail_restart_passwall'] == True:
                            try:
                                logging.info('配置文件中设置重启passwall, 检查OpenWRT连接情况...')
                                if is_host_online(config['openwrt']['host']):
                                    logging.info('配置文件中设置重启passwall, 开始执行...')
                                    if config['openwrt']['restart_mode'] == 0:
                                        passwall_restart()
                                    elif config['openwrt']['restart_mode'] == 1:
                                        op = Openwrt(host=config['openwrt']['host'], port=config['openwrt']['port'])
                                        errmsg = op.login(config['openwrt']['user'], config['openwrt']['pwd'])
                                        if errmsg:
                                            logging.error(f'openwrt登录失败, 错误信息->{errmsg}')
                                        else:
                                            token = op.passwall_get_token()
                                            logging.info(f'执行passwall重启返回信息->{op.passwall_restart(token)}')
                                        op.logout()
                                else:
                                    logging.info('openwrt不在线, 跳过重启passwall')
                            except TimeoutError:
                                logging.error('配置文件中设置重启passwall, 但是连接Openwrt超时, 可能是Openwrt未运行, 跳过重启passwall')
                            except Exception as e:
                                logging.error(e)
        except Exception as e:
            logging.error(e)
            if str(e).find('no login authentication') != -1:
                logging.info('爱快登录会话过期, 重新登录...')
                ikuai_logged = False
                continue
        time.sleep(config['check_interval'])