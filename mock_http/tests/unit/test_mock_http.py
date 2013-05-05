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

import logging
from unittest import TestCase
import httplib2
from mock_http import MockHTTP, GET, POST, UnexpectedURLException,\
     UnretrievedURLException, URLOrderingException, WrongBodyException,\
     AlreadyRetrievedURLException, WrongHeaderValueException,\
     WrongHeaderException, never, once, at_least_once
from random import randint
import sys

import threading

class TestMockHTTP(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.thread_active_init = threading.active_count()  # for httplib 
        cls.http = httplib2.Http()
        cls.server_port = randint(49152, 65535)
        cls.mock = MockHTTP(cls.server_port, shutdown_on_verify=False)

    @classmethod    
    def tearDownClass(cls):
        cls.mock.shutdown()
        
    def tearDown(self):
        self.mock.reset()
    
    def test_get_request(self):
        """Tests a get request that expects nothing to return but an 200."""
        
        self.mock.expects(method=GET, path='/index.html')
        resp, status = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port)
        self.assertEqual(resp['status'], '200')
        self.assert_(self.mock.verify())
    
    def test_get_request_wrong_url(self):
        """Tests a get request that expects a different URL."""
        
        self.mock.expects(method=GET, path='/index.html')
        resp, content = self.http.request(
            uri = 'http://localhost:%s/notindex.html' % self.server_port,
            method = 'GET')
        self.assertEqual(resp['status'], '404')
        self.assertRaises(UnexpectedURLException, self.mock.verify)
    
    def test_get_with_code(self):
        
        self.mock.expects(method=GET, path='/index.html').will(http_code=500)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method='GET')
        self.assertEqual(resp['status'], '500', 'Expected 500 response.')
        self.assert_(self.mock.verify())
    
    def test_get_with_body(self):
        """Tests a get request that returns a different URL."""
        test_body = 'Test response.'
        
        self.mock.expects(method=GET, path='/index.html').will(body=test_body)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertEqual(content, test_body)
        self.assert_(self.mock.verify())
    
    def test_get_with_header(self):
        """Tests a get request that includes a custom header."""
        test_header_name = 'Content-Type'
        test_header_contents = 'text/html'
        
        self.mock.expects(method=GET, path='/index.html').will(
            headers={test_header_name: test_header_contents})
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertTrue(resp[test_header_name.lower()].startswith(test_header_contents))
        self.assert_(self.mock.verify())
    
    def test_multiple_get(self):
        """Test getting a URL twice."""
        
        self.mock.expects(method=GET, path='/index.html')
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertEqual(resp['status'], '200')
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertEqual(resp['status'], '200')
        self.assert_(self.mock.verify())
    
    def test_never_get(self):
        """Test a URL that has a 'never' times on it."""
        
        self.mock.expects(method=GET, path='/index.html', times=never)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertEqual(resp['status'], '404')
        self.assertRaises(UnexpectedURLException, self.mock.verify)
    
    def test_get_once_got_twice(self):
        """Test getting a URL twice that expects to be retrieved once only."""
        
        self.mock.expects(method=GET, path='/index.html', times=once)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertEqual(resp['status'], '404')
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
        call = lambda: self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        [ call() for x in xrange(5) ]
        self.mock.verify()   

    def test_get_at_least_once_got_twice(self):
        """Test getting a URL twice that expects to be retrieved at least once."""
        
        self.mock.expects(method=GET, path='/index.html', times=at_least_once)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        self.assertEqual(resp['status'], '200')
        self.assert_(self.mock.verify())
    
    def test_get_at_least_once_got_never(self):
        """Test never getting a URL that expects to be retrieved at least once."""
        
        self.mock.expects(method=GET, path='/index.html', times=at_least_once)
        self.assertRaises(UnretrievedURLException, self.mock.verify)
    
    def test_get_after(self):
        """Test two URLs that expect to be retrieved in order."""
        test_body = 'Test POST body.\r\n'
        
        self.mock.expects(method=GET, path='/index.html', name='url #1')
        self.mock.expects(method=POST, path='/index.html', after='url #1', body=test_body)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'GET')
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body,
            headers={'content-type': 'text/plain'})
        self.assert_(self.mock.verify())

    def test_get_after_wrong_order(self):
        """Test two URLs that expect to be retrieved in order, but aren't."""
        test_body = 'Test POST body.\r\n'
        
        self.mock.expects(method=GET, path='/index.html', name='url #1')
        self.mock.expects(method=POST, path='/index.html', after='url #1', body=test_body)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body,
            headers = {'content-type': 'text/plain'})
        self.assertEqual(resp['status'], '404')
        self.assertRaises(URLOrderingException, self.mock.verify)
        
    def test_post(self):
        """Tests a POST request."""
        test_body = 'Test POST body.\r\n'
        
        self.mock.expects(method=POST, path='/index.html', body=test_body).will(http_code=201)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body,
            headers = {'content-type': 'text/plain'})
        self.assertEqual(resp['status'], '201')
        self.assert_(self.mock.verify())
    
    def test_post_bad_body(self):
        """Tests a POST request that sends the wrong body data."""
        test_body = 'Test POST body.\r\n'
        expected_body = 'Expected POST body.\r\n'
        
        self.mock.expects(method=POST, path='/index.html', body=expected_body)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body,
            headers = {'content-type': 'text/plain'})
        self.assertEqual(resp['status'], '404')
        self.assertRaises(WrongBodyException, self.mock.verify)
    
    def test_post_header(self):
        """Tests a POST request with some custom headers."""
        test_body = 'Test POST body.\r\n'
        test_headers = {'content-type': 'application/atom+xml; type=entry',
                        'content-length': str(len(test_body)),
                        'Slug': 'ooze',}
        
        self.mock.expects(method=POST, path='/index.html',
                     body=test_body, headers=test_headers).will(http_code=201)
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST',  body = test_body, headers=test_headers,)
        self.assertEqual(resp['status'], '201')
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
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body, headers = test_headers)
        self.assertEqual(resp['status'], '200')
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
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body, headers=test_headers)
        self.assertEqual(resp['status'], '404')
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
        resp, content = self.http.request(
            uri = 'http://localhost:%s/index.html' % self.server_port,
            method = 'POST', body = test_body, headers=test_headers)
        self.assertEqual(resp['status'], '404')
        self.assertRaises(WrongHeaderValueException, self.mock.verify)
