
import base64
import hashlib
import requests
import json


class iKuai:
    def __init__(self, scheme="http", host='192.168.1.1', port=80):
        self.__cookie = None
        self.scheme = scheme
        self.host = host
        self.port = port
        self.__base_url = '{}://{}:{}'.format(scheme, host, port)

    def login(self, username, password):
        json_data = {
            'username': username,
            'passwd': hashlib.md5(password.encode()).hexdigest(),
            'pass': base64.b64encode(('salt_11' + password).encode()).decode(),
            'remember_password': ''
        }

        # print(json_data)
        resp = requests.post(self.__base_url + '/Action/login', json=json_data)
        resp_json = json.loads(resp.text)
        raise_exception('登录', resp_json)
        self.__cookie = resp.cookies

    def logout(self):
        requests.post(self.__base_url + '/Action/logout', json={}, cookies=self.__cookie)

    def get_custom_isp_list(self):
        json_data = {"func_name": "custom_isp", "action": "show",
                     "param": {"TYPE": "total,data", "limit": "0,100", "ORDER_BY": "", "ORDER": ""}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('获取自定义运营商', resp_json)
        return resp_json['Data']['data']

    def set_custom_isp(self, name, id, content):
        json_data = {"func_name": "custom_isp", "action": "edit",
                     "param": {"id": id, "name": name, "ipgroup": content, "comment": ""}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('修改自定义运营商', resp_json)

    def create_custom_isp(self, name):
        json_data = {"func_name": "custom_isp", "action": "add", "param": {"name": name, "ipgroup": ","}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('创建自定义运营商', resp_json)
        return resp_json['RowId']

    def get_dns_config(self):
        json_data = {"func_name": "dns","action": "show","param": {"TYPE": "dns_config"}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('获取DNS配置', resp_json)
        return resp_json['Data']['data'][0]

    def set_dns_config(self, param):
        json_data = {
            "func_name": "dns",
            "action": "save",
            "param": param
        }
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('设置DNS配置', resp_json)

    def get_stream_ipport_list(self):
        json_data = {"func_name":"stream_ipport","action":"show","param":{"TYPE":"total,data","limit":"0,100","ORDER_BY":"","ORDER":""}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('获取端口分流列表', resp_json)
        return resp_json['Data']['data']

    def set_stream_ipport_enable(self, id, enable):
        action = 'up'
        if not enable:
            action = 'down'
        json_data = {"func_name": "stream_ipport", "action": action, "param":{"id": id}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception(f'修改端口分流状态{action}', resp_json)

    def get_natrule_list(self):
        json_data = {"func_name":"nat_rule","action":"show","param":{"TYPE":"total,data","limit":"0,100","ORDER_BY":"","ORDER":""}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('获取NAT规则列表', resp_json)
        return resp_json['Data']['data']

    def set_natrule_enable(self, id, enable):
        action = 'up'
        if not enable:
            action = 'down'
        json_data = {"func_name": "nat_rule", "action": action, "param": {"id": id}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception(f'修改端口分流状态{action}', resp_json)

    def get_ether_info(self):
        json_data = {"func_name": "homepage", "action": "show", "param": {"TYPE": "ether_info,snapshoot"}}
        resp = requests.post(self.__base_url + '/Action/call', json=json_data, cookies=self.__cookie)
        resp_json = json.loads(resp.text)
        raise_exception('获取网络接口信息', resp_json)
        return resp_json['Data']

    def get_ether_info_filter(self, wan_name):
        wan_list = self.get_ether_info()['snapshoot_wan']
        for wan in wan_list:
            if wan['interface'] == wan_name:
                return wan
        return None


def raise_exception(desc, json):
    if not str(json['ErrMsg']).lower().startswith('succ'):
        raise Exception('{}操作执行失败, 错误信息->{}'.format(desc, json['ErrMsg']))
