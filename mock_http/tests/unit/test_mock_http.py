from unittest import TestCase
import urllib2
import httplib
from mock_http import MockHTTP, GET, POST, UnexpectedURLException,\
     UnretrievedURLException, URLOrderingException, never, once, at_least_once
from random import randint

class TestMockHTTP(TestCase):
    def setUp(self):
        self.server_port = randint(49152, 65535)
    
    def test_get_request(self):
        """Tests a get request that expects nothing to return but an 200."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html')
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        resp.read()
        self.assert_(mock.verify())
    
    def test_get_request_wrong_url(self):
        """Tests a get request that expects a different URL."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html')
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen,
                          'http://127.0.0.1:%s/notindex.html' % self.server_port)
        self.assertRaises(UnexpectedURLException, mock.verify)
    
    def test_get_with_code(self):
        """Tests a get request that returns a different URL."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html').will(http_code=500)
        try:
            urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        except urllib2.HTTPError, e:
            self.assertEqual(e.code, 500)
        else:
            self.fail('Expected an HTTPError to be raised.')
        self.assert_(mock.verify())
    
    def test_get_with_body(self):
        """Tests a get request that returns a different URL."""
        test_body = 'Test response.'
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html').will(body=test_body)
        response = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        self.assertEqual(response.read(), test_body)
        self.assert_(mock.verify())
    
    def test_get_with_header(self):
        """Tests a get request that includes a custom header."""
        test_header_name = 'Content-type'
        test_header_contents = 'text/html'
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html').will(
            headers={test_header_name: test_header_contents})
        response = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        self.assertEqual(response.info().get(test_header_name),
                         test_header_contents)
        response.read()
        self.assert_(mock.verify())
    
    def test_multiple_get(self):
        """Test getting a URL twice."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html')
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        resp.read()
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        resp.read()
        self.assert_(mock.verify)
    
    def test_never_get(self):
        """Test a URL that has a 'never' times on it."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', times=never)
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen,
                          'http://127.0.0.1:%s/index.html' % self.server_port)
        self.assertRaises(UnexpectedURLException, mock.verify)
    
    def test_get_once_got_twice(self):
        """Test getting a URL twice that expects to be retrieved once only."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', times=once)
        urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen,
                          'http://127.0.0.1:%s/index.html' % self.server_port)
        self.assertRaises(UnexpectedURLException, mock.verify)
    
    def test_get_once_got_never(self):
        """Test never getting a URL that expects to be retrieved once only."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', times=once)
        self.assertRaises(UnretrievedURLException, mock.verify)
    
    def test_get_at_least_once_got_twice(self):
        """Test getting a URL twice that expects to be retrieved at least once."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', times=at_least_once)
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        resp.read()
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        resp.read()
        self.assert_(mock.verify)
    
    def test_get_at_least_once_got_never(self):
        """Test never getting a URL that expects to be retrieved at least once."""
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', times=at_least_once)
        self.assertRaises(UnretrievedURLException, mock.verify)
    
    def test_get_after(self):
        """Test two URLs that expect to be retrieved in order."""
        test_body = 'Test POST body.\r\n'
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', name='url #1')
        mock.expects(method=POST, path='/index.html', after='url #1', body=test_body)
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port)
        resp.read()
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port,
                                   test_body)
        resp.read()
        self.assert_(mock.verify())

    def test_get_after_wrong_order(self):
        """Test two URLs that expect to be retrieved in order, but aren't."""
        test_body = 'Test POST body.\r\n'
        mock = MockHTTP(self.server_port)
        mock.expects(method=GET, path='/index.html', name='url #1')
        mock.expects(method=POST, path='/index.html', after='url #1', body=test_body)
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen,
                     'http://127.0.0.1:%s/index.html' % self.server_port, test_body)
        self.assertRaises(URLOrderingException, mock.verify)
        
    def test_post(self):
        """Tests a POST request."""
        test_body = 'Test POST body.\r\n'
        mock = MockHTTP(self.server_port)
        mock.expects(method=POST, path='/index.html', body=test_body)
        resp = urllib2.urlopen('http://127.0.0.1:%s/index.html' % self.server_port,
                                   test_body)
        resp.read()
        self.assert_(mock.verify())
