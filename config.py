import logging
from typing import Dict, Any
from yaml import dump, load, SafeLoader
from error import ConfigurationError

# 配置类型提示
ConfigType = Dict[str, Any]
AdGuardConfig = Dict[str, Any]
OpenWrtConfig = Dict[str, Any]
IKuaiConfig = Dict[str, Any]

def create_sample_config(config_path: str) -> None:
    """创建示例配置文件"""
    sample_config = {
        "ikuai": {
            "host": "爱快路由器IP",
            "port": 80,
            "user": "admin",
            "pwd": "密码",
            "check_wan": "wan2",
        },
        "openwrt": {
            "host": "OpenWrt IP",
            "port": 80,
            "user": "root",
            "pwd": "密码",
            "ssh_port": 22,
            "check_dns_domain": ["itdog.cn", "ip.skk.moe"],
            "check_url": ["https://www.google.com/generate_204"],
            "onfail_restart_passwall": True
        },
        "adguardhome": [
            {
                "host": "AdGuardHome IP",
                "port": 80,
                "user": "admin",
                "pwd": "密码",
                "normal_upstream_dns": ["OpenWrt IP"],
                "onfail_upstream_dns": ["223.5.5.5"],
            }
        ],
        "check_interval": 30,
        "debug": False
    }

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            dump(sample_config, f, allow_unicode=True)
        logging.info("示例配置文件已创建，请修改后重新运行")
    except IOError as e:
        logging.error(f"创建示例配置文件失败: {str(e)}")
        raise ConfigurationError("无法创建配置文件") from e


def load_config(config_path: str) -> ConfigType:
    """加载并验证配置文件"""
    required_sections = ["ikuai", "openwrt", "adguardhome"]

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = load(f, Loader=SafeLoader)

        for section in required_sections:
            if section not in config:
                raise ConfigurationError(f"配置文件中缺少必要章节: {section}")

        return config
    except (IOError, KeyError) as e:
        logging.error(f"加载配置文件失败: {str(e)}")
        raise ConfigurationError("配置文件加载失败") from e