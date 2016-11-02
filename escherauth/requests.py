from __future__ import absolute_import

import requests

from escherauth.auth import EscherAuth
from escherauth.request import EscherRequest


class EscherRequestRequests(EscherRequest):
    def request_uri(self):
        return self.request.path_url

    def method(self):
        return self.request.method

    def host(self):
        return self.request.host

    def headers(self):
        return self.request.headers

    def set_header(self, header, value):
        self.request.headers[header] = value

    def body(self):
        return self.request.body or ''


class EscherRequestsAuth(requests.auth.AuthBase):
    def __init__(self, credential_scope, options, client):
        self.escher = EscherAuth(credential_scope, options)
        self.client = client

    def __call__(self, request):
        return self.escher.sign(request, self.client)
