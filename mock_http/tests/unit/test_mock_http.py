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

import tornado.web
from tornado.testing import AsyncTestCase, AsyncHTTPTestCase
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPClient, HTTPError
from mock_http import MockHTTP, GET, POST, UnexpectedURLException, \
    UnretrievedURLException, URLOrderingException, WrongBodyException, \
    AlreadyRetrievedURLException, WrongHeaderValueException, \
    WrongHeaderException, never, once, at_least_once
import logging as log



class TestTornadoAppWithMockHttp(AsyncHTTPTestCase):
    """
    Ensure that we're able to mock http services and use
    AsyncHTTPTestCase at the same time
    """
    def setUp(self):
        self.mock = MockHTTP()
        super(TestTornadoAppWithMockHttp, self).setUp()


    def get_app(self):
        url = self.mock.get_url("foo.bar.baz")
        class TestHandler(tornado.web.RequestHandler):

            def get(self, *args, **kwargs):
                client = HTTPClient()
                log.debug("sent request")
                try:
                    resp = client.fetch(HTTPRequest(
                        method="GET",
                        url=url,
                        request_timeout=1,
                        connect_timeout=1
                    ))
                except HTTPError, e:
                    if e.code == 599:
                        self.set_status(500, reason=str(e))
                        self.finish(str(e))
                        return
                    else:
                        self.set_status(e.code)
                        self.finish(str(e))
                        return
                self.set_status(resp.code)
                log.debug("got response: %s" % resp.body)
                self.finish(resp.body)

        return tornado.web.Application([
            (".*", TestHandler, {})
        ])

    def test_mock_call(self):
        self.mock.expects(GET, path='/foo.bar.baz', times=once).will(body="boom!")
        resp = self.fetch("/boom!")
        self.assertEquals(resp.body, "boom!")
        self.mock.verify()

    def test_mock_timeout_call(self):
        self.mock.expects(GET, path='/foo.bar.baz', times=once).will(body="boom!", delay=3)
        resp = self.fetch("/boom!")
        self.assertEquals(resp.body, "HTTP 599: Timeout")
        self.assertEquals(resp.code, 500)
        self.mock.verify()

    def tearDown(self):
        self.mock.shutdown()


class TestMockHTTP(AsyncTestCase):

    def setUp(self):
        super(TestMockHTTP, self).setUp()
        self.mock = MockHTTP()
        self.http_client = AsyncHTTPClient(io_loop=self.io_loop)

    def tearDown(self):
        self.mock.shutdown()
        self.http_client.close()
        super(TestMockHTTP, self).tearDown()

    def fetch(self, path, **kwargs):
        """Convenience method to synchronously fetch a url.

        The given path will be appended to the local server's host and
        port.  Any additional kwargs will be passed directly to
        `.AsyncHTTPClient.fetch` (and so could be used to pass
        ``method="POST"``, ``body="..."``, etc).
        """

        self.http_client.fetch(
            HTTPRequest(url=self.mock.get_url(path), **kwargs),
        callback=self.stop)
        return self.wait()

    def test_get_request(self):
        """Tests a get request that expects nothing to return but an 200."""
        
        self.mock.expects(method=GET, path='/index.html')
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 200)
        self.assert_(self.mock.verify())
    
    def test_get_request_wrong_url(self):
        """Tests a get request that expects a different URL."""
        
        self.mock.expects(method=GET, path='/index.html')
        resp = self.fetch(method="GET", path="notindex.html")
        self.assertEqual(resp.code, 404)
        self.assertRaises(UnexpectedURLException, self.mock.verify)
    
    def test_get_with_code(self):
        
        self.mock.expects(method=GET, path='/index.html').will(http_code=500)
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 500, 'Expected 500 response.')
        self.assert_(self.mock.verify())
    
    def test_get_with_body(self):
        """Tests a get request that returns a different URL."""
        test_body = 'Test response.'
        
        self.mock.expects(method=GET, path='/index.html').will(body=test_body)
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.body, test_body)
        self.assert_(self.mock.verify())
    
    def test_get_with_header(self):
        """Tests a get request that includes a custom header."""
        test_header_name = 'Content-Type'
        test_header_contents = 'text/html'
        
        self.mock.expects(method=GET, path='/index.html').will(
            headers={test_header_name: test_header_contents})
        resp = self.fetch(method="GET", path="index.html")
        self.assertTrue(resp.headers[test_header_name].startswith(test_header_contents))
        self.assert_(self.mock.verify())
    
    def test_multiple_get(self):
        """Test getting a URL twice."""
        
        self.mock.expects(method=GET, path='/index.html')
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 200)
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 200)
        self.assert_(self.mock.verify())
    
    def test_never_get(self):
        """Test a URL that has a 'never' times on it."""
        
        self.mock.expects(method=GET, path='/index.html', times=never)
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 404)
        self.assertRaises(UnexpectedURLException, self.mock.verify)
    
    def test_get_once_got_twice(self):
        """Test getting a URL twice that expects to be retrieved once only."""
        
        self.mock.expects(method=GET, path='/index.html', times=once)
        resp = self.fetch(method="GET", path="index.html")
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 404)
        self.assertRaises(AlreadyRetrievedURLException, self.mock.verify)
    
    def test_get_once_got_never(self):
        """Test never getting a URL that expects to be retrieved once only."""
        
        self.mock.expects(method=GET, path='/index.html', times=once)
        self.assertRaises(UnretrievedURLException, self.mock.verify)
    
    def test_get_5times_got_never(self):
        """Test never getting a URL that expects to be retrieved 5 times only."""
        
        self.mock.expects(method=GET, path='/index.html', times=5)
        self.assertRaises(UnretrievedURLException, self.mock.verify)   

    def test_get_5times_got_5times(self):
        """Test getting 5 times a URL that expects to be retrieved 5 times"""
        
        self.mock.expects(method=GET, path='/index.html', times=5)
        call = lambda: self.fetch('/index.html')
        [ call() for x in xrange(5) ]
        self.mock.verify()   

    def test_get_at_least_once_got_twice(self):
        """Test getting a URL twice that expects to be retrieved at least once."""
        
        self.mock.expects(method=GET, path='/index.html', times=at_least_once)
        resp = self.fetch(method="GET", path="index.html")
        self.assertEqual(resp.code, 200)
        self.assert_(self.mock.verify())
    
    def test_get_at_least_once_got_never(self):
        """Test never getting a URL that expects to be retrieved at least once."""
        
        self.mock.expects(method=GET, path='/index.html', times=at_least_once)
        self.assertRaises(UnretrievedURLException, self.mock.verify)
    
    def test_get_after(self):
        """Test two URLs that expect to be retrieved in order."""
        test_body = 'Test POST body.\r\n'
        headers = {'content-type': 'text/plain'}
        self.mock.expects(method=GET, path='/index.html', name='url #1')
        self.mock.expects(method=POST, path='/index.html', after='url #1', headers=headers, body=test_body)
        self.fetch(method="GET", path="index.html")
        self.fetch(method="POST", path="index.html", body = test_body, headers=headers)
        self.assert_(self.mock.verify())

    def test_get_after_wrong_order(self):
        """Test two URLs that expect to be retrieved in order, but aren't."""
        test_body = 'Test POST body.\r\n'
        headers = {'content-type': 'text/plain'}
        self.mock.expects(method=GET, path='/index.html', name='url #1')
        self.mock.expects(method=POST, path='/index.html', after='url #1', body=test_body, headers=headers)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = headers)
        self.assertEqual(resp.code, 404)
        self.assertRaises(URLOrderingException, self.mock.verify)
        
    def test_post(self):
        """Tests a POST request."""
        test_body = 'Test POST body.\r\n'
        headers = {'content-type': 'text/plain'}
        self.mock.expects(method=POST, path='/index.html', body=test_body, headers=headers).will(http_code=201)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = headers)
        self.assertEqual(resp.code, 201)
        self.assert_(self.mock.verify())
    
    def test_post_bad_body(self):
        """Tests a POST request that sends the wrong body data."""
        test_body = 'Test POST body.\r\n'
        expected_body = 'Expected POST body.\r\n'
        headers = {'content-type': 'text/plain'}
        self.mock.expects(method=POST, path='/index.html', body=expected_body)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = headers)
        self.assertEqual(resp.code, 404)
        self.assertRaises(WrongBodyException, self.mock.verify)
    
    def test_post_header(self):
        """Tests a POST request with some custom headers."""
        test_body = 'Test POST body.\r\n'
        test_headers = {'content-type': 'application/atom+xml; type=entry',
                        'content-length': str(len(test_body)),
                        'Slug': 'ooze',}
        
        self.mock.expects(method=POST, path='/index.html',
                     body=test_body, headers=test_headers).will(http_code=201)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = test_headers)
        self.assertEqual(resp.code, 201)
        self.assert_(self.mock.verify())

    def test_post_unexpected_header(self):
        """Tests a POST request with an unexpected header."""
        test_body = 'Test POST body.\r\n'
        test_headers = {'content-type': 'application/atom+xml; type=entry',
                        'content-length': str(len(test_body)),
                        'Slug': 'ooze',}
        expected_headers = {'content-type': 'application/atom+xml; type=entry',
                            'content-length': str(len(test_body)),}
        
        self.mock.expects(method=POST, path='/index.html',
                     body=test_body, headers=expected_headers)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = test_headers)
        self.assertEqual(resp.code, 200)
        self.assert_(self.mock.verify())

    def test_post_missing_header(self):
        """Tests a POST request without an expected header."""
        test_body = 'Test POST body.\r\n'
        test_headers = {'content-type': 'application/atom+xml; type=entry',
                        'content-length': str(len(test_body)),}
        expected_headers = {'content-type': 'application/atom+xml; type=entry',
                            'content-length': str(len(test_body)),
                            'Slug': 'ooze',}
        
        self.mock.expects(method=POST, path='/index.html',
                     body=test_body, headers=expected_headers)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = test_headers)
        self.assertEqual(resp.code, 404)
        self.assertRaises(WrongHeaderException, self.mock.verify)
    
    def test_post_unexpected_header_value(self):
        """Tests a POST request with an unexpected header value."""
        test_body = 'Test POST body.\r\n'
        test_headers = {'content-type': 'application/atom+xml; type=entry',
                        'content-length': str(len(test_body)),
                        'Slug': 'ooze',}
        expected_headers = {'content-type': 'application/atom+xml; type=entry',
                        'content-length': str(len(test_body)),
                        'Slug': 'slime',}
        
        self.mock.expects(method=POST, path='/index.html',
                     body=test_body, headers=expected_headers)
        resp = self.fetch('/index.html', method = 'POST', body = test_body, headers = test_headers)
        self.assertEqual(resp.code, 404)
        self.assertRaises(WrongHeaderValueException, self.mock.verify)
