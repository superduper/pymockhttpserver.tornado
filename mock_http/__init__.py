#!/usr/bin/env python
# Copyright 2010 O'Reilly Media, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Build a mock HTTP server that really works to unit test web service-dependent programs."""

from collections import defaultdict, namedtuple
import copy
import logging as log
import socket
import threading
import time
from tornado import netutil
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import RequestHandler, Application


__all__ = ['GET', 'POST', 'PUT', 'DELETE', 'never', 'once', 'at_least_once',
           'MockHTTP']

GET = 'GET'
POST = 'POST'
PUT = 'PUT'
DELETE = 'DELETE'

class ExpectedTime(object):

    def passes_test(self, invoked_times):
        raise NotImplementedError

class times(ExpectedTime):

    def __init__(self, times):
        self.times = times

    def passes_test(self, invoked_times):
        return invoked_times == self.times

class at_least(ExpectedTime):

    def __init__(self, times):
        self.times = times

    def passes_test(self, invoked_times):
        return invoked_times >= self.times

at_least_once = at_least(1)
once = times(1)
never = times(0)

def bind_unused_port():
    """Binds a server socket to an available port on localhost.

    Returns a tuple (socket, port).
    """
    [sock] = netutil.bind_sockets(0, 'localhost', family=socket.AF_INET)
    port = sock.getsockname()[1]
    return sock, port


class MockHTTPException(Exception):
    """Raised when something unexpected goes wrong in MockHTTP's guts."""
    pass

class MockHTTPExpectationFailure(Exception):
    """Parent class for exceptions describing how a MockHTTP has failed to live
    up to expectations."""
    pass

class UnexpectedURLException(MockHTTPExpectationFailure):
    """Raised when MockHTTP had gotten a request for an unexpected URL."""
    pass

class AlreadyRetrievedURLException(MockHTTPExpectationFailure):
    """Raised when MockHTTP has gotten a request for a URL that can't be retrieved again."""
    pass

class UnretrievedURLException(MockHTTPExpectationFailure):
    """Raised when MockHTTP has not gotten a request for a URL that it needed to get a request for."""
    pass

class URLOrderingException(MockHTTPExpectationFailure):
    """Raised when MockHTTP got requests for URLs in the wrong order."""
    pass

class WrongBodyException(MockHTTPExpectationFailure):
    """Raised when MockHTTP got a request with the wrong body."""
    pass

class WrongHeaderException(MockHTTPExpectationFailure):
    """Raised when MockHTTP got a request with an invalid header."""
    pass

class WrongHeaderValueException(MockHTTPExpectationFailure):
    """Raised when MockHTTP got a request with an invalid header value."""
    pass

class WrongParamException(MockHTTPExpectationFailure):
    """Raised when MockHTTP got a request with an invalid param."""
    pass

class WrongParamValueException(MockHTTPExpectationFailure):
    """Raised when MockHTTP got a request with an invalid param value."""
    pass

class Expectation(object):
    """A request that a MockHTTP server is expecting. Don't construct these
    directly, use :meth:`MockHTTP.expects`"""
    def __init__(self, mock, method, path, body=None, headers=None, times=None,
                 name=None, after=None, params=None):
        self.mock = mock
        self.method = method
        self.path = path
        self.request_body = body
        # Ensure that nothing else can modify these after the mock is created.
        self.request_params = copy.copy(params)
        self.request_headers = copy.copy(headers)
        self.response_delay = 0
        self.response_code = 200
        self.response_headers = {}
        self.response_body = ''
        self.times = times
        self.invoked = False
        self.invoked_times = 0
        self.failure = None
        self.name = name
        if name is not None:
            self.mock.expected_by_name[name] = self
        if after is not None:
            self.after = self.mock.expected_by_name[after]
        else:
            self.after = None
    
    def will(self, http_code=None, headers=None, body=None, delay=0):
        """Specifies what to do in response to a matching request.
        
        :param http_code: The HTTP code to send. *Default:* 200 OK.
        :param headers: The HTTP headers to send, specified as a dictionary\
        mapping header to value. *Default:* No headers are sent.
        :param body: A string object containing the HTTP body to send. To send\
        unicode, first encode it to utf-8. (And probably include an appropriate\
        content-type header.) *Default:* No body is sent.
        :returns: This :class:`Expectation` object."""
        if http_code is not None:
            self.response_code = http_code
        if body is not None:
            self.response_body = body
        if headers is not None:
            self.response_headers = headers
        log.debug("Will respond with code=%s, headers=%s, body=%s at %s", http_code, headers, body, self)
        self.response_delay = delay
        return self
    
    def check(self, method, path, params, headers, body):
        """Check this Expectation against the given request."""
        try:
            self._check_headers(method, path, headers)
            self._check_params(method, path, params)
            self._check_body(method, path, body)
            self._check_times(method, path)
            self._check_order(method, path)
            return True
        except MockHTTPExpectationFailure, e:
            self.failure = e
            raise
    
    def _check_headers(self, method, path, headers):
        if self.request_headers:
            for header, value in self.request_headers.iteritems():
                if header not in headers:
                    raise WrongHeaderException(
                        'Expected header missing on %s %s: %s' %\
                        (method, path, header))
                elif headers[header] != value:
                    raise WrongHeaderValueException(
                        'Wrong value for %s on %s %s. Expected: %r Got: %r' %\
                        (header, method, path, value, headers[header]))
    
    def _check_params(self, method, path, params):
        if self.request_params:
            for param, value in self.request_params.iteritems():
                if param not in params:
                    raise WrongParamException(
                        'Expected param missing on %s %s: %s' %\
                        (method, path, param))
                elif params[param] != value:
                    raise WrongParamValueException(
                        'Wrong value for %s on %s %s. Expected: %r Got: %r' %\
                        (param, method, path, value, params[param]))
    
    def _check_body(self, method, path, body):
        if self.request_body is not None and body != self.request_body:
            self.mock.wrong_body = True
            raise WrongBodyException(
                '%s %s: Expected request body %r Got: %r' %\
                (method, path, self.request_body, body))
    
    def _check_times(self, method, path):
        if self.times is never:
            raise UnexpectedURLException('%s %s, expected never' %\
                                         (method, path))
        elif self.times is once and self.invoked:
            raise AlreadyRetrievedURLException('%s %s twice, expected once' %\
                                               (method, path))
        elif isinstance(self.times, int) and self.invoked_times >= self.times \
                and (self.times > 0 and not self.invoked):
            raise UnexpectedURLException('%s %s %s times, expected %s times' %\
                                       (method, path, self.invoked_times, self.times))
    
    def _check_order(self, method, path):
        if self.after is not None and not self.after.invoked:
            self.mock.out_of_order = True
            raise URLOrderingException('%s %s expected only after %s %s' %
                                       (method, path,
                                        self.after.method, self.after.path))
    
    def response_data(self):
        """Respond to a request."""
        self.invoked = True
        self.invoked_times += 1
        if self.response_delay > 0 :
            time.sleep(self.response_delay)
        return (self.response_code, self.response_headers, self.response_body)

    def __repr__(self):
        return "<Expectation at %s method=%s, path=%s, times=%s>" % \
                (id(self), self.method, self.path, self.times )

def _http_server_thread(mock, io_loop):
    mock.server = HTTPServer(
        Application([
            (r".*", MockHandler, {"mock": mock})
        ], debug=True), io_loop=io_loop
    )
    mock.server.add_sockets([mock.sock])
    mock.server.start()
    io_loop.start()

class MockHTTP(object):
    """A Mock HTTP Server for unit testing web services calls.
    
    Basic Usage::
    
         mock_server = MockHTTP(42424)
         mock_server.expects(GET, '/index.html').will(body='A HTML body.')
         mock_server.expects(GET, '/asdf').will(http_code=404)
         urlopen('http://localhost:42424/index.html').read() == 'A HTML body.'
         urlopen('http://localhost:42424/asdf') # HTTPError: 404
         mock_server.verify()"""
    
    def __init__(self, shutdown_on_verify=True):
        """Create a MockHTTP server listening on localhost at the given port."""
        self.shutdown_on_verify = shutdown_on_verify
        self._server_io_loop = IOLoop()
        self.reset()
        self.sock, self.port = bind_unused_port()
        self.server_address = "http://localhost:%s" % self.port
        self._server_is_down = False
        self.thread = threading.Thread(target=_http_server_thread,
                                       kwargs=dict(io_loop=self._server_io_loop, mock=self))
        self.thread.start()

    def get_url(self, path):
        if not path.startswith("/"):
            return self.get_url("/" + path)
        return self.server_address + path


    def expects(self, method, path, *args, **kwargs):
        """Declares an HTTP Request that this MockHTTP expects.
        
        :param method: The HTTP method expected to use to access this URL.
        :param path: The expected path segment of this URL.
        :param body: The expected contents of the request body, as a string. If\
        you expect to send unicode, encode it as utf-8 first. *Default:* The\
        contents of the request body are irrelevant.
        :param params: Expected query parameters as a dictionary mapping query\
        parameter name to expected value. Checks to make sure that all expected\
        query parameters are present and have specified values. *Default:* No\
        query parameters are expected.
        :param headers: Expected headers as a dictionary mapping header name to\
        expected value. Checks to make sure that all expected headers are\
        present and have the specified values. *Default:* No headers are\
        required.
        :param times: The number of times this URL expects to be requested. Use\
        mock_http.never, mock_http.once, or mock_http.at_least_once for this.\
        *Default:* It does not matter how many times the URL is accessed.
        :param name: A name that can be used to refer to this expectation later.\
        *Default:* The expectation has no name.
        :param after: This URL must be accessed after a previously-named URL.\
        *Default:* The URL can be accessed at any time.
        :returns: The :class:`Expectation` object describing how this URL is\
        expected. You'll probably want to call :meth:`Expectation.will` on it\
        to describe how the URL should be responded to.
        """
        expectation = Expectation(self, method, path, *args, **kwargs)
        self.expected[method][path] = expectation
        log.debug("Added expectation: %s at %s", expectation, self)
        return expectation

    def reset(self):
        """
        Clears expectations
        """
        self.last_failure = None
        self.expected = defaultdict(dict)
        self.expected_by_name = {}
        log.debug("Reset expectations MockHTTP %s", self)

    def shutdown(self):
        """Close down the server"""
        if not self._server_is_down:
            log.debug("Shutting down %s", self)
            self._server_io_loop.stop()
            log.debug("Shutdown %s: Ok", self)
            self._server_is_down = True
        else:
            log.debug("Attempt to shut down server when its already down")
    
    def verify(self):
        """Close down the server and verify that this MockHTTP has met all its
        expectations.
        
        :returns: True, if all went as expected.
        :raises MockHTTPExpectationFailure: Or a subclass, describing the last\
        unexpected thing that happened."""
        if self.shutdown_on_verify:
            log.debug("Shutting down before verify %s", self)
            self.shutdown()
        if self.last_failure is not None:
            raise self.last_failure
        for method, expected in self.expected.iteritems():
            for path, expectation in expected.iteritems():
                if (isinstance(expectation.times, int) and expectation.times != expectation.invoked_times) or \
                   (isinstance(expectation.times, ExpectedTime)
                    and not expectation.times.passes_test(expectation.invoked_times)):
                    raise UnretrievedURLException("%s not %s" % (path, method))
        return True
    
    def is_expected(self, method, path, params, headers, body):
        """Test to see whether a request is expected.
        
        .. todo::
            Gracefully handle multiple expectations for the same URL and method.
        
        :raises MockHTTPExpectationFailure: Or a subclass, describing why this\
        request is unexpected.
        :returns: The :class:`Expectation` object that expects this request."""
        try:
            log.debug("Looking for [%s %s] at expectations", method, path) 
            expectation = self.expected[method][path]
            log.debug("Found [%s %s] matching expectation %s", method, path, expectation) 
            if expectation.check(method, path, params, headers, body):
                return expectation
        except KeyError:
            failure = UnexpectedURLException('Unexpected URL: %s' % path)
            self.last_failure = failure
            log.debug("Didnt found [%s %s] at expectations", method, path)
            raise failure
        except MockHTTPExpectationFailure, failure:
            self.last_failure = failure
            log.debug("Expectation %s check failed at [%s %s] with %s", expectation, method, path, failure) 
            raise



class MockHandler(RequestHandler):

    def initialize(self, mock):
        self.mock = mock


    def head(self, *args, **kwargs):
        return self.on_request() 

    def get(self, *args, **kwargs):
        return self.on_request()

    def post(self, *args, **kwargs):
        return self.on_request() 

    def delete(self, *args, **kwargs):
        return self.on_request() 

    def patch(self, *args, **kwargs):
        return self.on_request() 

    def put(self, *args, **kwargs):
        return self.on_request() 

    def options(self, *args, **kwargs):
        return self.on_request() 

    @property
    def all_arguments(self):
        r = dict()
        for k in self.request.arguments.iterkeys():
            v = self.get_argument(name=k)
            r[k]=v
        return r

    def on_request(self):
        r = self.request

        try:
            status, headers, body = self.mock.is_expected(
                r.method, r.path, self.all_arguments,
                r.headers, r.body
            ).response_data()

            self.set_status(status)
            map(lambda s: self.set_header(*s), headers.items())
            log.debug("Served with :%s " % body)
            self.finish(body)

        except MockHTTPException, failure:
            return self.mock_fail(failure)
        except MockHTTPExpectationFailure, failure:
            return self.mock_fail(failure)

    def mock_fail(self, message=None):
        """Standardized mechanism for reporting failure."""
        self.mock.failed_url = self.request.path
        self.set_status(404)
        self.finish('404 %s' % message)


