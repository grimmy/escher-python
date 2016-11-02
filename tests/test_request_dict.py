import unittest

from escherauth.dict import EscherRequestDict


class EscherRequestTest(unittest.TestCase):
    def test_object_basic(self):
        request = EscherRequestDict({
            'method': 'GET',
            'host': 'host.foo.com',
            'uri': '/?foo=bar',
            'headers': [
                ('Date', 'Mon, 09 Sep 2011 23:36:00 GMT'),
                ('Host', 'host.foo.com'),
            ],
        })
        self.assertEqual(request.method(), 'GET')
        self.assertEqual(request.host(), 'host.foo.com')
        self.assertEqual(request.path(), '/')
        self.assertListEqual(request.query(), [
            ('foo', 'bar'),
        ])
        self.assertListEqual(request.headers(), [
            ('Date', 'Mon, 09 Sep 2011 23:36:00 GMT'),
            ('Host', 'host.foo.com'),
        ])
        self.assertEqual(request.body(), '')  # there was no body specified

    def test_object_complex(self):
        request = EscherRequestDict({
            'method': 'POST',
            'host': 'host.foo.com',
            'uri': '/example/path/?foo=bar&abc=cba',
            'headers': {},
            'body': 'HELLO WORLD!',
        })
        self.assertEqual(request.method(), 'POST')
        self.assertEqual(request.host(), 'host.foo.com')
        self.assertEqual(request.path(), '/example/path/')
        print(request.query())
        self.assertListEqual(request.query(), [
            ('foo', 'bar'),
            ('abc', 'cba'),
        ])
        self.assertDictEqual(request.headers(), {})
        self.assertEqual(request.body(), 'HELLO WORLD!')

    def test_object_set_header(self):
        request = EscherRequestDict({
            'method': 'POST',
            'host': 'host.foo.com',
            'uri': '/example/path/?foo=bar&abc=cba',
            'headers': {},
            'body': 'HELLO WORLD!',
        })
        request.set_header('Foo', 'Bar')
        self.assertDictEqual(request.headers(), {'Foo': 'Bar'})
