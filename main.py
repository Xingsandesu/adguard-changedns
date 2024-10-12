#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from traceback import print_exc
from argparse import ArgumentParser
from atexit import register
from sys import exit
from os import path

from adguardhome import AdGuardHome
from dns_client.adapters.requests import DNSClientSession

from dns.resolver import Resolver
from paramiko import SSHClient, AutoAddPolicy
from yaml import SafeLoader, dump, load

import requests
import logging
import time
import gc

from openwrt import Openwrt
from ikuai import iKuai

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
    # filename=log_path,
    # filemode='a',
)
logging.getLogger('dns_client').setLevel(logging.WARNING)

def create_sample_config(config_path):
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
    with open(config_path, 'w', encoding='utf-8') as f:
        dump(sample_config, f, allow_unicode=True)
    logging.info('示例配置文件已创建, 请修改后重新运行')
    exit(0)

'''
废置代码
from ping3 import ping
def is_host_online(hostname) -> bool:
    response = ping(hostname)
return response
'''

# 检查域名是否可以解析
def can_be_resolv(host) -> bool:
    try:
        resolver = Resolver()
        resolver.nameservers = [config['openwrt']['host']]
        resolver.resolve(host)
    except Exception:
        return False
    return True


# 检查URL是否可以通过HTTP访问
def can_be_http(url, custom_dns=None, timeout=5) -> bool:
    try:
        if custom_dns:
            with DNSClientSession(custom_dns) as session:
                session.head(url, timeout=timeout)
        else:
            requests.head(url, timeout=timeout)
    except Exception:
        return False
    return True

# 检查网络状态
def check_network(ikuai) -> str:
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
        if not can_be_http(url, config['openwrt']['host']):
            return f'访问国外网站{url}失败'
    return ''

'''
# 重启passwall服务
def passwall_restart():
    with SSHClient() as ssh_connect:
        ssh_connect.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh_connect.connect(config['openwrt']['host'],
                                config['openwrt']['ssh_port'],
                                config['openwrt']['user'],
                                config['openwrt']['pwd'])
            ssh_connect.exec_command("uci set passwall.@global[0].enabled='0'")
            ssh_connect.exec_command('uci commit passwall')
            ssh_connect.exec_command('/sbin/reload_config')
            time.sleep(3)
            ssh_connect.exec_command("uci set passwall.@global[0].enabled='1'")
            ssh_connect.exec_command('uci commit passwall')
            ssh_connect.exec_command('/sbin/reload_config')
            logging.info('passwall重启完成')
        except Exception as e:
            logging.error(f'重启passwall服务时出错: {e}')
'''
# 重启passwall服务
def passwall_restart():
    ssh_connect = SSHClient()
    ssh_connect.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh_connect.connect(config['openwrt']['host'],
                            config['openwrt']['ssh_port'],
                            config['openwrt']['user'],
                            config['openwrt']['pwd'])
        ssh_connect.exec_command("uci set passwall.@global[0].enabled='0'")
        ssh_connect.exec_command('uci commit passwall')
        ssh_connect.exec_command('/sbin/reload_config')
        time.sleep(3)
        ssh_connect.exec_command("uci set passwall.@global[0].enabled='1'")
        ssh_connect.exec_command('uci commit passwall')
        ssh_connect.exec_command('/sbin/reload_config')
        logging.info(f'passwall重启完成')
    finally:
        ssh_connect.close()
# 设置AdGuardHome的上游DNS
def set_adg_upstream(host, port, username, password, upstream_dns_list):
    try:
        adguard = AdGuardHome(host=host, port=port, username=username, password=password)
        adguard.set_upstream_dns(upstream_dns_list)
    except Exception as e:
        error_message = str(e)
        if "forbidden" in error_message:
            logging.error("AdGuardHome认证错误: 访问被拒绝，请检查您的用户名和密码是否正确。")
            exit(1)
        else:
            logging.error(f"AdGuardHomeError: {error_message}")
            exit(1)
        

if __name__ == '__main__':
    # 解析命令行参数
    parser = ArgumentParser()
    parser.add_argument('--config', '-c', type=str, help='配置文件路径', default='config.yaml')
    parser.add_argument('--debug', action='store_true', help='启用内存泄漏检查')
    parser.add_argument('--gc', action='store_true', help='启用手动垃圾回收')
    args = vars(parser.parse_args())
    try:
        if not path.exists(args['config']):
            create_sample_config(args['config'])
    
        # 加载配置文件
        with open(args['config'], 'r', encoding='utf-8') as f:
            config = load(f, SafeLoader)
        logging.info('配置文件已加载')
    except Exception as e:
        logging.error(f'加载配置文件时出错: {e}')
        create_sample_config(args['config'])
        logging.error('示例配置文件已恢复, 请重新修改后重新运行')
        exit(1)

    if args['debug']:
        import tracemalloc
        tracemalloc.start()

    prev_errmsg = '.'
    ikuai_logged = False
    ikuai = iKuai(host=config['ikuai']['host'], port=config['ikuai']['port'])
    register(ikuai.logout)

    while True:
        if args['debug']:
            snapshot1 = tracemalloc.take_snapshot()
        try:
            if not ikuai_logged:
                ikuai.login(config['ikuai']['user'], config['ikuai']['pwd'])
                ikuai_logged = True
            errmsg = check_network(ikuai)
            if not errmsg:
                if prev_errmsg:
                    for adg in config['adguardhome']:
                        set_adg_upstream(adg['host'], adg['port'],
                                             adg['user'], adg['pwd'],
                                             adg['normal_upstream_dns'])
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
                                fail_count += 1
                            else:
                                logging.info('网络恢已复, 取消重新检测')
                                break
                            time.sleep(config['openwrt']['retry_interval'])

                    if fail_count == config['openwrt']['retry_count']:
                        logging.info(f'重新检测全部失败')
                        for adg in config['adguardhome']:
                            set_adg_upstream(adg['host'], adg['port'],
                                                 adg['user'], adg['pwd'],
                                                 adg['onfail_upstream_dns'])
                            logging.error(
                                f'错误信息->{errmsg}, 已经将adguardhome {adg["host"]}上游dns切换为{adg["onfail_upstream_dns"]}')
                        if config['openwrt']['onfail_restart_passwall'] == True:
                            try:
                                logging.info('配置文件中设置重启passwall, 检查OpenWRT连接情况...')
                                if can_be_http(f"http://{config['openwrt']['host']}:{config['openwrt']['port']}", timeout=1):
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
                                print_exc()
                                logging.error('配置文件中设置重启passwall, 但是连接Openwrt超时, 可能是Openwrt未运行, 跳过重启passwall')
                            except Exception as e:
                                print_exc()
                                logging.error(e)
                        
        except KeyboardInterrupt:
            logging.info('检测程序已退出')
            exit(0)
        except Exception as e:
            print_exc()
            logging.error(e)
            if 'no login authentication' in str(e):
                logging.info('爱快登录会话过期, 重新登录...')
                ikuai_logged = False
                continue
        time.sleep(config['check_interval'])
        
                    
        
        if args['debug']:
            snapshot2 = tracemalloc.take_snapshot()
            top_stats = snapshot2.compare_to(snapshot1, 'lineno')
            logging.info("[ Top 10 differences ]")
            for stat in top_stats[:10]:
                logging.info(f"{'*' * 60}\nFile: {stat.traceback[0].filename}\nLine: {stat.traceback[0].lineno}\nSize: {stat.size_diff / 1024:.1f} KiB\nCount: {stat.count_diff}\n{'*' * 60}")
            
            # 打印占用内存最多的
            largest_stat = max(top_stats, key=lambda stat: stat.size_diff)
            logging.info(f"{'*' * 60}\n占用内存最多的:\nFile: {largest_stat.traceback[0].filename}\nLine: {largest_stat.traceback[0].lineno}\nSize: {largest_stat.size_diff / 1024:.1f} KiB\nCount: {largest_stat.count_diff}\n{'*' * 60}")
            
            
        if args['gc']:
            #counts_before = gc.get_count()
            #print(f'清理前: {counts_before}')
            gc.collect()
            #counts_after = gc.get_count()
            #print(f'清理后: {counts_after}')
            
            # 计算清理的对象数量
            #cleared_objects = counts_before[0] - counts_after[0]
            #logging.info(f'清理了 {cleared_objects} 个对象')