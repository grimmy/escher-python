from __future__ import absolute_import

from escherauth.request import EscherRequest


class EscherRequestDict(EscherRequest):
    def request_uri(self):
        return self.request['uri']

    def method(self):
        return self.request['method']

    def host(self):
        return self.request['host']

    def headers(self):
        return self.request['headers']

    def body(self):
        return self.request.get('body', '')

    def set_header(self, name, value):
        self.request['headers'][name] = value
