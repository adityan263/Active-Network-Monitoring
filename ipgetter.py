#!/usr/bin/env python
import re
import random

from sys import version_info

PY3K = version_info >= (3, 0)

if PY3K:
    import urllib.request as urllib
else:
    import urllib2 as urllib


__version__ = "0.6"


def myip():
    return IPgetter().get_externalip()


class IPgetter(object):

    def __init__(self):
        self.server_list = ['http://ip.dnsexit.com',
                            'http://ifconfig.me/ip',
                            'http://echoip.com',
                            'http://ipecho.net/plain',
                            'http://www.infosniper.net/',
                            'https://wtfismyip.com/text',
                            'http://ipinfo.io/',
                            'http://httpbin.org/ip',
                            'https://v4.ident.me']

    def get_externalip(self):

        myip = ''
        for i in range(7):
            myip = self.fetch(random.choice(self.server_list))
            if myip != '':
                return myip
            else:
                continue
        return ''

    def fetch(self, server):
        url = None
        opener = urllib.build_opener()
        opener.addheaders = [('User-agent',
                              "Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0")]

        try:
            url = opener.open(server, timeout=2)
            content = url.read()

            # Didn't want to import chardet. Prefered to stick to stdlib
            if PY3K:
                try:
                    content = content.decode('UTF-8')
                except UnicodeDecodeError:
                    content = content.decode('ISO-8859-1')

            m = re.search(
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                content)
            myip = m.group(0)
            return myip if len(myip) > 0 else ''
        except Exception:
            return ''
        finally:
            if url:
                url.close()

    def test(self):

        resultdict = {}
        for server in self.server_list:
            resultdict.update(**{server: self.fetch(server)})

        ips = sorted(resultdict.values())
        ips_set = set(ips)
        print('\nNumber of servers: {}'.format(len(self.server_list)))
        print("IP's :")
        for ip, ocorrencia in zip(ips_set, map(lambda x: ips.count(x), ips_set)):
            print('{0} = {1} ocurrenc{2}'.format(ip if len(ip) > 0 else 'broken server', ocorrencia, 'y' if ocorrencia == 1 else 'ies'))
        print('\n')
        print(resultdict)

if __name__ == '__main__':
    print(myip())
