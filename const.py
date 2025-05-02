from enum import Enum

# 常量定义
DEFAULT_CHECK_INTERVAL = 30
REQUEST_TIMEOUT = 5

class NetworkStatus(Enum):
    """网络状态枚举"""
    HEALTHY = 0
    DEGRADED = 1