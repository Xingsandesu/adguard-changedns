import json

import requests
import bs4
import lxml
import time


class Openwrt:
    def __init__(self, scheme="http", host='192.168.1.1', port=80):
        self.__cookie = None
        self.scheme = scheme
        self.host = host
        self.port = port
        self.__base_url = '{}://{}:{}'.format(scheme, host, port)

    def login(self, username, password):
        d = {
            'luci_username': username,
            'luci_password': password
        }
        resp = requests.post(self.__base_url + '/cgi-bin/luci/',
                             data=d, cookies=self.__cookie, allow_redirects=False)
        if resp.status_code == 403:
            soup = bs4.BeautifulSoup(resp.text, 'lxml')
            errmsg = soup.find(attrs={'class': 'errorbox'})
            return errmsg
        if resp.status_code == 302:
            self.__cookie = resp.cookies
            return None

    def logout(self):
        requests.get(self.__base_url + '/cgi-bin/luci/admin/logout', cookies=self.__cookie)

    def passwall_get_token(self):
        resp = requests.get(self.__base_url + '/cgi-bin/luci/admin/services/passwall', cookies=self.__cookie)
        soup = bs4.BeautifulSoup(resp.text, 'lxml')
        return soup.find('input', attrs={'name': 'token'})['value']

    def passwall_check_baidu(self):
        resp = requests.get(self.__base_url + f'/cgi-bin/luci/admin/services/passwall/connect_status?type=baidu&url=http%3A%2F%2Fwww.baidu.com&{int(round(time.time() * 1000))}', cookies=self.__cookie)
        return json.loads(resp.text)

    def passwall_check_google(self):
        resp = requests.get(self.__base_url + f'/cgi-bin/luci/admin/services/passwall/connect_status?type=google&url=http%3A%2F%2Fwww.google.com%2Fgenerate_204&{int(round(time.time() * 1000))}', cookies=self.__cookie)
        return json.loads(resp.text)

    def passwall_restart(self, token):
        d = {
            'token': token
        }
        resp = requests.post(self.__base_url + '/cgi-bin/luci/servicectl/restart/passwall', data=d, cookies=self.__cookie)
        return resp.text
