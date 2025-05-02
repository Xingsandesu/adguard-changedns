import base64
import hashlib
import logging
import requests
from json import JSONDecodeError
from typing import Dict, Any
from const import REQUEST_TIMEOUT
from error import NetworkCheckError


class IKuaiClient:
    """爱快路由器客户端"""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.base_url = f"http://{host}:{port}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self._login()

    def _login(self) -> None:
        """执行登录并维护会话状态"""
        login_data = {
            "username": self.username,
            "passwd": hashlib.md5(self.password.encode()).hexdigest(),
            "pass": base64.b64encode(f"salt_11{self.password}".encode()).decode(),
            "remember_password": ""
        }

        try:
            response = self.session.post(
                f"{self.base_url}/Action/login",
                json=login_data,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            self._validate_login_response(response.json())
        except requests.exceptions.RequestException as e:
            raise NetworkCheckError(f"登录请求失败: {str(e)}") from e

    def _validate_login_response(self, response_data: dict) -> None:
        """验证登录响应"""
        if not response_data.get("Result") != 0:
            error_msg = response_data.get("ErrMsg", "未知错误")
            raise NetworkCheckError(f"登录验证失败: {error_msg}")

    def _call_api(self, endpoint: str, payload: dict, max_retries: int = 2) -> dict:
        """带会话状态检查的API调用"""
        for attempt in range(max_retries + 1):
            try:
                response = self.session.post(
                    f"{self.base_url}/Action/call",
                    json=payload,
                    timeout=REQUEST_TIMEOUT
                )
                response_data = response.json()

                # 检查会话过期错误
                if response_data.get("Result") == 10014:
                    logging.warning("检测到会话过期，尝试重新登录...")
                    self._login()
                    continue

                response.raise_for_status()
                return response_data

            except requests.exceptions.HTTPError as e:
                if attempt == max_retries:
                    raise NetworkCheckError(f"API请求失败: {str(e)}") from e
            except JSONDecodeError as e:
                raise NetworkCheckError("响应解析失败") from e

        raise NetworkCheckError("API请求达到最大重试次数")

    def get_interface_info(self, interface: str) -> Dict[str, Any]:
        """获取指定接口信息（带会话管理）"""
        payload = {
            "func_name": "monitor_iface",
            "action": "show",
            "param": {"TYPE": "iface_check"}
        }

        try:
            response_data = self._call_api("/Action/call", payload)
            for iface in response_data.get("Data", {}).get("iface_check", []):
                if iface.get("interface") == interface:
                    return iface
            raise NetworkCheckError(f"未找到指定接口: {interface}")
        except KeyError as e:
            raise NetworkCheckError("响应格式异常") from e