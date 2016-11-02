import datetime
import unittest

from nose_parameterized import parameterized

from escherauth.auth import EscherAuth
from escherauth.dict import EscherRequestDict


def read_request(suite, test, extension='req'):
    file = open('tests/' + suite + '_testsuite/' + test + '.' + extension, 'r')
    lines = (file.read() + "\n").splitlines()
    file.close()

    method, uri = lines[0].split(' ')[0:2]
    headers = {}
    for header in lines[1:-2]:
        key, value = header.split(':', 1)
        headers[key] = value.lstrip()
    body = lines[-1]

    return EscherRequestDict({
        'method': method,
        'host': 'host.foo.com',
        'uri': uri,
        'headers': headers,
        'body': body,
    })


class EscherAuthAmazonTest(unittest.TestCase):
    def setUp(self):
        self.escher = EscherAuth('us-east-1/host/aws4_request', {
            'algo_prefix': 'AWS4',
            'vendor_key': 'AWS4',
            'hash_algo': 'SHA256',
            'auth_header_name': 'Authorization',
            'date_header_name': 'Date',
            'current_time': datetime.datetime(2011, 9, 9, 23, 36)
        })

    @parameterized.expand([
        ('get-header-value-trim'),
        ('get-relative'),
        ('get-relative-relative'),
        ('get-slash'),
        ('get-slash-dot-slash'),
        ('get-slash-pointless-dot'),
        ('get-slashes'),
        ('get-space'),
        ('get-unreserved'),
        ('get-utf8'),
        ('get-vanilla'),
        ('get-vanilla-empty-query-key'),
        ('get-vanilla-query'),
        ('get-vanilla-query-order-key'),
        ('get-vanilla-query-order-key-case'),
        ('get-vanilla-query-order-value'),
        ('get-vanilla-query-unreserved'),
        ('get-vanilla-ut8-query'),
        ('post-header-key-case'),
        ('post-header-key-sort'),
        ('post-header-value-case'),
        ('post-vanilla'),
        ('post-vanilla-empty-query-value'),
        ('post-vanilla-query'),
        ('post-vanilla-query-nonunreserved'),
        ('post-vanilla-query-space'),
        ('post-x-www-form-urlencoded'),
        ('post-x-www-form-urlencoded-parameters'),
    ])
    def test_signing(self, testcase):
        self.maxDiff = None

        suite = 'aws4'
        request = read_request(suite, testcase)
        request_signed = read_request(suite, testcase, 'sreq')
        headers_to_sign = [x.lower() for x in request.headers().keys()]
        request = self.escher.sign(request, {
            'api_key': 'AKIDEXAMPLE',
            'api_secret': 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        }, headers_to_sign)
        self.assertEqual(request.get('method'), request_signed.method())
        self.assertEqual(request.get('host'), request_signed.host())
        self.assertEqual(request.get('uri'), request_signed.request_uri())
        self.assertDictEqual(
            request.get('headers'),
            request_signed.headers(),
        )
        self.assertEqual(request.get('body'), request_signed.body())
