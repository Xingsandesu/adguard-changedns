#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import time
import logging
import argparse
from os import path
from sys import exit
from typing import List
from traceback import format_exc
from netcheck import NetworkMonitor
from openwrt import PasswallManager
from adguardhome import AdGuardHomeClient
from error import ConfigurationError, NetworkCheckError
from config import create_sample_config, load_config, ConfigType


# 初始化日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s",
)

def main():
    """主程序逻辑"""
    parser = argparse.ArgumentParser(description="网络健康监控脚本")
    parser.add_argument("-c", "--config", default="config.yaml", help="配置文件路径")
    args = parser.parse_args()

    try:
        # 初始化配置
        if not path.exists(args.config):
            create_sample_config(args.config)
            return

        config = load_config(args.config)
        if config.get("debug", False):
            logging.getLogger().setLevel(logging.DEBUG)

        # 初始化组件
        monitor = NetworkMonitor(config)
        adguard_clients = [AdGuardHomeClient(ag) for ag in config["adguardhome"]]

        # 主循环
        while True:
            try:
                current_status = monitor.check_network_status()
                if current_status:
                    if monitor.is_first_failure:
                        handle_network_failure(config, adguard_clients)
                else:
                    if monitor.is_first_recovery:
                        for ad in adguard_clients:
                            ad.update_normal_dns()

            except KeyboardInterrupt:
                logging.info("程序已手动终止")
                return
            except Exception as e:
                logging.error(f"运行时错误: {str(e)}")
                logging.debug(f"错误详情: {format_exc()}")
            time.sleep(config["check_interval"])


    except ConfigurationError as e:
        logging.error(f"配置错误: {str(e)}")
        exit(1)
    except Exception as e:
        logging.error(f"致命错误: {str(e)}")
        exit(1)


def handle_network_failure(config: ConfigType, adguard_clients: List[AdGuardHomeClient]) -> None:
    """处理网络故障情况"""
    # 切换AdGuardHome DNS
    for client in adguard_clients:
        try:
            client.update_on_fail_dns()
        except NetworkCheckError as e:
            logging.error(f"AdGuardHome更新失败: {str(e)}")

    # 重启Passwall服务
    if config["openwrt"].get("onfail_restart_passwall", False):
        try:
            manager = PasswallManager(config["openwrt"])
            manager.restart_via_ssh()
        except NetworkCheckError as e:
            logging.error(f"Passwall重启失败: {str(e)}")


if __name__ == "__main__":
    main()