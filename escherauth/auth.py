from __future__ import absolute_import

import datetime
import hmac
import re

from hashlib import sha256, sha512

try:
    from urllib import quote
except:
    from urllib.parse import quote


class EscherAuth(object):
    _normalize_path = re.compile('([^/]+/\.\./?|/\./|//|/\.$|/\.\.$)')

    def __init__(self, credential_scope, options={}):
        self.credential_scope = credential_scope
        self.algo_prefix = options.get('algo_prefix', 'ESR')
        self.vendor_key = options.get('vendor_key', 'Escher')
        self.hash_algo = options.get('hash_algo', 'SHA256')
        self.current_time = options.get(
            'current_time',
            datetime.datetime.utcnow()
        )
        self.auth_header_name = options.get(
            'auth_header_name',
            'X-Escher-Auth'
        )
        self.date_header_name = options.get(
            'date_header_name',
            'X-Escher-Date'
        )
        self.clock_skew = options.get('clock_skew', 300)
        self.algo = self.create_algo()
        self.algo_id = self.algo_prefix + '-HMAC-' + self.hash_algo

    def sign(self, request, client, headers_to_sign=[]):
        for header in [self.date_header_name.lower(), 'host']:
            if header not in headers_to_sign:
                headers_to_sign.append(header)

        signature = self.generate_signature(
            client['api_secret'],
            request,
            headers_to_sign
        )

        header_fmt = (
            '{algorithm} ' +
            'Credential={api_key}/{date_stamp}/{scope}' +
            ', SignedHeaders={signed_headers}' +
            ', Signature={signature}'
        )

        header = header_fmt.format(
            algorithm=self.algo_id,
            api_key=client['api_key'],
            date_stamp=self.short_date(self.current_time),
            scope=self.credential_scope,
            signed_headers=self.prepare_headers_to_sign(headers_to_sign),
            signature=signature,
        )

        request.set_header(self.auth_header_name, header)

        return request.request

    def hmac_digest(self, key, message, is_hex=False):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        digest = hmac.new(key, message.encode('utf-8'), self.algo)
        if is_hex:
            return digest.hexdigest()
        return digest.digest()

    def generate_signature(self, api_secret, req, headers_to_sign):
        canonicalized_request = self.canonicalize(req, headers_to_sign)
        string_to_sign = self.get_string_to_sign(canonicalized_request)

        signing_key = self.hmac_digest(
            self.algo_prefix + api_secret,
            self.short_date(self.current_time)
        )

        for data in self.credential_scope.split('/'):
            signing_key = self.hmac_digest(signing_key, data)

        return self.hmac_digest(signing_key, string_to_sign, True)

    def canonicalize(self, req, headers_to_sign):
        return "\n".join([
            req.method(),
            self.canonicalize_path(req.path()),
            self.canonicalize_query(req.query()),
            self.canonicalize_headers(req.headers(), headers_to_sign),
            '',
            self.prepare_headers_to_sign(headers_to_sign),
            self.algo(req.body().encode('utf-8')).hexdigest()
        ])

    def canonicalize_path(self, path):
        changes = 1
        while changes > 0:
            path, changes = self._normalize_path.subn('/', path, 1)
        return path

    def canonicalize_headers(self, headers, headers_to_sign):
        headers_list = []

        for key in iter(sorted(headers.keys())):
            if key.lower() in headers_to_sign:
                normalized = self.normalize_white_spaces(headers[key])
                headers_list.append(key.lower() + ':' + normalized)

        return "\n".join(sorted(headers_list))

    def normalize_white_spaces(self, value):
        index = 0
        value_normalized = []
        pattern = re.compile(r'\s+')
        for part in value.split('"'):
            if index % 2 == 0:
                part = pattern.sub(' ', part)
            value_normalized.append(part)
            index += 1
        return '"'.join(value_normalized).strip()

    def canonicalize_query(self, query_parts):
        safe = "~+!'()*"
        query_list = []

        for key, value in query_parts:
            quoted_key = quote(key, safe=safe)
            quoted_value = quote(value, safe=safe)
            query_list.append(quoted_key + '=' + quoted_value)

        return "&".join(sorted(query_list))

    def get_string_to_sign(self, canonicalized_request):
        return "\n".join([
            self.algo_id,
            self.long_date(self.current_time),
            self.short_date(self.current_time) + '/' + self.credential_scope,
            self.algo(canonicalized_request.encode('utf-8')).hexdigest()
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
