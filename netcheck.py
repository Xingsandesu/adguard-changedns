import logging
import time
import requests
from dns.resolver import Resolver
from typing import Optional, List, Any
from config import ConfigType
from ikuai import IKuaiClient
from traceback import format_exc
from const import REQUEST_TIMEOUT, NetworkStatus
from dns_client.adapters.requests import DNSClientSession

class DNSResolver:
    """DNS解析检查工具类"""

    @staticmethod
    def can_resolve(domain: str, nameserver: str) -> bool:
        """检查域名是否能被解析"""
        resolver = Resolver()
        resolver.nameservers = [nameserver]
        try:
            resolver.resolve(domain)
            return True
        except Exception:
            logging.debug(f"错误详情: {format_exc()}")
            return False


class HTTPChecker:
    """HTTP可用性检查工具类"""

    @staticmethod
    def is_accessible(
            url: str,
            dns_server: str = None
    ) -> bool:
        """检查URL是否可达"""
        try:
            if dns_server:
                with DNSClientSession(dns_server, timeout=REQUEST_TIMEOUT) as req:
                    response = req.head(url, timeout=REQUEST_TIMEOUT)
            else:
                response = requests.head(url, timeout=REQUEST_TIMEOUT)
            return response.status_code < 400
        except Exception as e:
            logging.debug(f"访问URL失败: {url}, 错误: {str(e)}")
            logging.debug(f"错误详情: {format_exc()}")
            return False


class NetworkMonitor:
    """网络状态监测器（增强日志控制）"""

    def __init__(self, config: ConfigType):
        self.config = config
        self.previous_status = NetworkStatus.HEALTHY
        self.current_errors = []
        # 用于跟踪各检测项的独立状态
        self.status_history = {
            "wan": None,
            "dns": [],
            "http": []
        }
        self.last_status_change = time.time()
        self.error_counter = 0
        self.normal_counter = 0

        self.ikuai_client = IKuaiClient(
            host=self.config["ikuai"]["host"],
            port=self.config["ikuai"]["port"],
            username=self.config["ikuai"]["user"],
            password=self.config["ikuai"]["pwd"],
        )

    def check_network_status(self) -> str:
        """执行网络检查并返回合并错误信息"""
        current_errors = []

        # WAN状态检查
        wan_error = self._check_wan_connection()
        if wan_error:
            current_errors.append(wan_error)
            self._update_status("wan", wan_error)
        else:
            self._update_status("wan", None)

        # DNS检查
        dns_errors = self._check_dns_resolution()
        current_errors.extend(dns_errors)
        self._update_status("dns", dns_errors)

        # HTTP检查
        http_errors = self._check_http_access()
        current_errors.extend(http_errors)
        self._update_status("http", http_errors)

        return self._handle_status_transition(current_errors)

    def _check_wan_connection(self) -> Optional[str]:
        """检查爱快WAN口连接状态"""
        try:
            wan_info = self.ikuai_client.get_interface_info(
                self.config["ikuai"]["check_wan"]
            )
            if wan_info.get("errmsg") != "线路检测成功":
                return f"爱快 {self.config['ikuai']['check_wan']} 线路异常"
        except Exception as e:
            return f"获取WAN口状态失败: {str(e)}"
        return None

    def _check_dns_resolution(self) -> List[str]:
        """检查DNS解析"""
        errors = []
        openwrt_ip = self.config["openwrt"]["host"]

        for domain in self.config["openwrt"]["check_dns_domain"]:
            if not DNSResolver.can_resolve(domain, openwrt_ip):
                errors.append(f"DNS解析失败: {domain}")
        return errors

    def _check_http_access(self) -> List[str]:
        """检查HTTP访问"""
        errors = []
        for url in self.config["openwrt"]["check_url"]:
            if not HTTPChecker.is_accessible(url=url, dns_server=self.config["openwrt"]["host"]):
                errors.append(f"HTTP访问失败: {url}")
        return errors

    def _update_status(self, check_type: str, errors: Any):
        """更新各检测项的状态历史"""
        if check_type == "wan":
            self.status_history["wan"] = bool(errors)
        elif check_type == "dns":
            self.status_history["dns"] = errors if errors else []
        elif check_type == "http":
            self.status_history["http"] = errors if errors else []

    def _handle_status_transition(self, current_errors: list) -> str:
        """处理状态转换和日志输出"""
        new_status = NetworkStatus.DEGRADED if current_errors else NetworkStatus.HEALTHY
        error_msg = "; ".join(current_errors) if current_errors else ""

        # 状态变化检测
        if new_status != self.previous_status:
            # 状态变更时重置计数器
            if new_status == NetworkStatus.HEALTHY:
                self.normal_counter = 1
                self.error_counter = 0
            else:
                self.error_counter = 1
                self.normal_counter = 0

            self._log_status_change(new_status, error_msg)
            self.last_status_change = time.time()
        else:
            # 持续状态时更新计数器
            if new_status == NetworkStatus.HEALTHY:
                self.normal_counter += 1
            else:
                self.error_counter += 1

        self.previous_status = new_status
        return error_msg

    @property
    def is_first_recovery(self) -> bool:
        """是否首次恢复健康状态"""
        return self.previous_status == NetworkStatus.HEALTHY and self.normal_counter == 1

    @property
    def is_first_failure(self) -> bool:
        """是否首次出现故障"""
        return self.previous_status == NetworkStatus.DEGRADED and self.error_counter == 1

    @staticmethod
    def _log_status_change(new_status: NetworkStatus, error_msg: str):
        """处理状态变更日志"""
        if new_status == NetworkStatus.DEGRADED:
            logging.warning(f"🚨 网络状态降级检测 -> {error_msg}")
        else:
            logging.info(f"✅ 网络恢复正常")

    def _get_last_errors(self) -> str:
        """获取合并后的历史错误信息"""
        errors = []
        if self.status_history["wan"]:
            errors.append(self.status_history["wan"])
        errors.extend(self.status_history["dns"])
        errors.extend(self.status_history["http"])
        return "; ".join(errors)