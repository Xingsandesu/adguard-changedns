import requests
from requests.auth import HTTPBasicAuth

class AdGuardHome:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.__base_url = 'http://{}:{}'.format(host, port)
        self.__basicauth = HTTPBasicAuth(username, password)
        self.__session = requests.Session()
        self.__session.auth = self.__basicauth

    def set_upstream_dns(self, upstream_dns):
        json_data = {"upstream_dns": upstream_dns}
        try:
            resp = self.__session.post(self.__base_url + '/control/dns_config', json=json_data)
            raise_exception('设置上游DNS服务器', resp)
        finally:
            self.__session.close()

def raise_exception(desc, resp):
    if resp.status_code != 200:
        raise Exception('{}操作执行失败, 错误信息->{}'.format(desc, resp.text.lower()))