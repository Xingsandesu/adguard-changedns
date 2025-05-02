import logging
import requests
from typing import List
from requests.auth import HTTPBasicAuth
from config import AdGuardConfig
from const import REQUEST_TIMEOUT
from error import NetworkCheckError


class AdGuardHomeClient:
    """AdGuardHome 客户端"""

    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.base_url = f"http://{config['host']}:{config['port']}"
        self.auth = HTTPBasicAuth(config['user'], config['pwd'])
        self.session = requests.Session()
        self.session.auth = self.auth

    def _update_dns_servers(self, servers: List[str]) -> None:
        """更新上游DNS服务器"""
        try:
            response = self.session.post(
                f"{self.base_url}/control/dns_config",
                json={"upstream_dns": servers},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            logging.info(f"Adguardhome服务器 {self.config['host']}:{self.config['port']} 的上游DNS服务器已更新为: {','.join(servers)}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                raise NetworkCheckError("AdGuardHome 认证失败") from e
            raise NetworkCheckError(f"DNS更新失败: {e.response.text}") from e
        except requests.exceptions.RequestException as e:
            raise NetworkCheckError(f"连接AdGuardHome失败: {str(e)}") from e

    def update_normal_dns(self):
        self._update_dns_servers(self.config["normal_upstream_dns"])

    def update_on_fail_dns(self):
        self._update_dns_servers(self.config["onfail_upstream_dns"])