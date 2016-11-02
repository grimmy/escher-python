import abc
import re

try:
    from urlparse import parse_qsl
except ImportError:
    from urllib.parse import parse_qsl


_URI_REGEX = re.compile('([^?#]*)(\?(.*))?')


class EscherRequest(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, request):
        self.request = request

        match = re.match(_URI_REGEX, self.request_uri())
        self._path = match.group(1)
        query_str = match.group(3)

        self._query = parse_qsl((query_str or '').replace(';', '%3b'), True)

    @abc.abstractmethod
    def method(self):
        """Returns the method for the request"""

    @abc.abstractmethod
    def host(self):
        """Returns the hostname for the request"""

    @abc.abstractmethod
    def headers(self):
        """Returns the headers as a dictionary for the request"""

    @abc.abstractmethod
    def set_header(self, header, value):
        """Sets the given header to value for the request"""

    @abc.abstractmethod
    def body(self):
        """Returns the body for the request"""

    def path(self):
        return self._path

    def query(self):
        return self._query
