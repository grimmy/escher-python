import datetime
import hmac
import requests

from hashlib import sha256, sha512
from urlparse import urlparse, parse_qsl


class EscherRequestsAuth(requests.auth.AuthBase):
    def __init__(self, credential_scope, options, client):
        self.escher = Escher(credential_scope, options)
        self.client = client

    def __call__(self, request):
        return self.escher.sign(request, self.client)


class EscherRequest():
    def __init__(self, request):
        self.type = type(request)
        self.request = request

    def request(self):
        return self.request

    def method(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.method
        if self.type is dict:
            return self.request['method']

    def host(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.host
        if self.type is dict:
            return self.request['host']

    def path(self):
        if self.type is requests.models.PreparedRequest:
            path_url = urlparse(self.request.path_url)
            return path_url.path
        if self.type is dict:
            path_url = urlparse(self.request['uri'])
            return path_url.path

    def query_parts(self):
        if self.type is requests.models.PreparedRequest:
            path_url = urlparse(self.request.path_url)
            return parse_qsl(path_url.query)
        if self.type is dict:
            path_url = urlparse(self.request['uri'])
            return parse_qsl(path_url.query)

    def headers(self):
        if self.type is requests.models.PreparedRequest:
            headers = []
            for key, value in self.request.headers.iteritems():
                headers.append([key, value])
            return headers
        if self.type is dict:
            return self.request['headers']

    def body(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.body or ''
        if self.type is dict:
            return self.request.get('body', '')

    def add_header(self, header, value):
        if self.type is requests.models.PreparedRequest:
            self.request.headers[header] = value
        if self.type is dict:
            self.request['headers'].append((header, value))


class Escher:
    def __init__(self, credential_scope, options={}):
        self.credential_scope = credential_scope
        self.algo_prefix = options.get('algo_prefix', 'ESR')
        self.vendor_key = options.get('vendor_key', 'Escher')
        self.hash_algo = options.get('hash_algo', 'SHA256')
        self.current_time = options.get('current_time', datetime.datetime.utcnow())
        self.auth_header_name = options.get('auth_header_name', 'X-Escher-Auth')
        self.date_header_name = options.get('date_header_name', 'X-Escher-Date')
        self.clock_skew = options.get('clock_skew', 900)
        self.algo = self.create_algo()
        self.algo_id = self.algo_prefix + '-HMAC-' + self.hash_algo

    def sign(self, r, client, headers_to_sign=[]):
        request = EscherRequest(r)

        for header in [self.date_header_name.lower(), 'host']:
            if header not in headers_to_sign:
                headers_to_sign.append(header)

        signature = self.generate_signature(client['api_secret'], request, headers_to_sign)
        request.add_header(self.auth_header_name, ", ".join([
            self.algo_id + ' Credential=' + client['api_key'],
            'SignedHeaders=' + self.prepare_headers_to_sign(headers_to_sign),
            'Signature=' + signature
        ]))
        return request.request

    def generate_signature(self, api_secret, req, headers_to_sign):
        canonicalized_request = self.canonicalize(req, headers_to_sign)
        string_to_sign = self.get_string_to_sign(canonicalized_request)

        signing_key = hmac.new(self.algo_prefix + api_secret, self.short_date(self.current_time), self.algo).digest()
        for data in self.credential_scope.split('/'):
            signing_key = hmac.new(signing_key, data, self.algo).digest()

        return hmac.new(signing_key, string_to_sign, self.algo).hexdigest()

    def canonicalize(self, req, headers_to_sign):
        return "\n".join([
            req.method(),
            req.path(),
            self.canonicalize_query(req.query_parts()),
            self.canonicalize_headers(req.headers()),
            '',
            self.prepare_headers_to_sign(headers_to_sign),
            self.algo(req.body()).hexdigest()
        ])

    def canonicalize_headers(self, headers):
        headers_list = []
        for key, value in iter(sorted(headers)):
            headers_list.append(key.lower() + ':' + value)
        return "\n".join(headers_list)

    def canonicalize_query(self, query_parts):
        query_list = []
        for key, value in query_parts:
            query_list.append(key + '=' + value)
        return "&".join(sorted(query_list))

    def get_string_to_sign(self, canonicalized_request):
        return "\n".join([
            self.algo_id,
            self.long_date(self.current_time),
            self.short_date(self.current_time) + '/' + self.credential_scope,
            self.algo(canonicalized_request).hexdigest()
        ])

    def create_algo(self):
        if self.hash_algo == 'SHA256':
            return sha256
        if self.hash_algo == 'SHA512':
            return sha512

    def long_date(self, time):
        return time.strftime('%Y%m%dT%H%M%SZ')

    def short_date(self, time):
        return time.strftime('%Y%m%d')

    def prepare_headers_to_sign(self, headers_to_sign):
        return ";".join(sorted(headers_to_sign))