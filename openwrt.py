import logging
from paramiko.client import SSHClient, AutoAddPolicy
from config import OpenWrtConfig
from const import REQUEST_TIMEOUT
from error import NetworkCheckError


class PasswallManager:
    """Passwall服务管理器"""

    def __init__(self, config: OpenWrtConfig):
        self.config = config

    def restart_via_ssh(self) -> None:
        """通过SSH重启服务"""
        try:
            with SSHClient() as ssh:
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                ssh.connect(
                    hostname=self.config["host"],
                    port=self.config["ssh_port"],
                    username=self.config["user"],
                    password=self.config["pwd"],
                    timeout=REQUEST_TIMEOUT,
                )

                commands = [
                    "uci set passwall.@global[0].enabled='0'",
                    "uci commit passwall",
                    "/sbin/reload_config",
                    "sleep 3",
                    "uci set passwall.@global[0].enabled='1'",
                    "uci commit passwall",
                    "/sbin/reload_config",
                ]

                for cmd in commands:
                    ssh.exec_command(cmd)

            logging.info("Passwall 服务已通过SSH重启")
        except Exception as e:
            logging.error(f"SSH操作失败: {str(e)}")
            raise NetworkCheckError("Passwall重启失败") from e