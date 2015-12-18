"""Tests for letsencrypt-auto"""

from contextlib import contextmanager
from functools import partial
from os import curdir, environ, pardir
from os.path import dirname, join, split, splitdrive
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from posixpath import normpath
from shutil import rmtree
import socket
import ssl
from subprocess import check_call
from tempfile import mkdtemp
from threading import Thread
from unittest import TestCase
from urllib import unquote

from nose.tools import eq_, nottest

from letsencrypt_auto.build import build as build_le_auto


class RequestHandler(SimpleHTTPRequestHandler):
    """An HTTPS request handler which is quiet and serves a specific folder."""

    def __init__(self, *args, **kwargs):
        """
        :arg root: The path to the folder to serve

        """
        self.root = kwargs.pop('root')  # required kwarg
        SimpleHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, format, *args):
        """Don't log each request to the terminal."""

    # Adapted from the implementation in the superclass
    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax, rooting
        them at self.root.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = normpath(unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = self.root
        for word in words:
            drive, word = splitdrive(word)
            head, word = split(word)
            if word in (curdir, pardir):
                continue
            path = join(path, word)
        return path


@nottest
def tests_dir():
    """Return a path to the "tests" directory."""
    return dirname(__file__)


def server_and_port():
    """Return an unstarted HTTPS server and the port it will use."""
    # Find a port, and bind to it. I can't get the OS to close the socket
    # promptly after we shut down the server, so we typically need to try
    # a couple ports after the first test case. Setting
    # TCPServer.allow_reuse_address = True seems to have nothing to do
    # with this behavior.
    worked = False
    for port in xrange(4443, 4543):
        try:
            server = HTTPServer(('localhost', port),
                                partial(RequestHandler,
                                        root=join(tests_dir(), 'server_root')))
        except socket.error:
            pass
        else:
            worked = True
            server.socket = ssl.wrap_socket(
                server.socket,
                certfile=join(tests_dir(), 'certs/servers/localhost/server.pem'),
                server_side=True)
            break
    if not worked:
        raise RuntimeError("Couldn't find an unused socket for the testing HTTPS server.")
    return server, port


@contextmanager
def ephemeral_dir():
    dir = mkdtemp(prefix='le-test-')
    try:
        yield dir
    finally:
        rmtree(dir)


class ServerTestCase(TestCase):
    """Support for tests which use a local HTTPS server"""

    @classmethod
    def setup_class(cls):
        """Spin up an HTTP server pointing at a small, local package index."""
        cls.server, cls.port = server_and_port()
        cls.thread = Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()
        cls.thread.join()

    @classmethod
    def server_url(cls):
        return 'https://localhost:{port}/'.format(port=cls.port)


def signed(content, private_key):
    """Return the signed SHA-256 hash of ``content``, using the given key."""


def run_le_auto(venv_dir, base_url):
    """Run the prebuilt version of letsencrypt-auto, returning stdout and
    stderr strings.

    If the command returns other than 0, raise CalledProcessError.

    """
    out = StringIO()
    err = StringIO()
    env = {'XDG_DATA_HOME': venv_dir,
           'LE_AUTO_JSON_URL': base_url + 'letsencrypt/json',
           'LE_AUTO_DIR_TEMPLATE': base_url + '%s/'}
    check_call('letsencrypt-auto',
               shell=True,
               stdout=out,
               stderr=err,
               env=env)
    return out, err


class AutoTests(ServerTestCase):
    def test_all(self):
        """Exercise most branches of letsencrypt-auto.

        The branches:

        * An le-auto upgrade is needed.
        * An le-auto upgrade is not needed.
        * There was an out-of-date LE script installed.
        * There was a current LE script installed.
        * There was no LE script installed. (not that important)
        * Peep verification passes.
        * Peep has a hash mismatch.
        * The OpenSSL sig mismatches.

        I violate my usual rule of having small, decoupled tests, because...

        1. We shouldn't need to run a Cartesian product of the branches: the
           phases run in separate shell processes, containing state leakage
           pretty effectively. The only shared state is FS state, and it's
           limited to a temp dir, assuming (if we dare) all functions properly.
        2. One combination of branches happens to set us up nicely for testing
           the next, saving code.

        At the moment, we let bootstrapping run. We probably wanted those
        packages installed anyway for local development.

        For tests which get this far, we run merely ``letsencrypt --version``.
        The functioning of the rest of the letsencrypt script is covered by
        other test suites.

        """
        PRIVATE_KEY = ''
        NEW_LE_AUTO = build_le_auto(version='99.9.9')
        NEW_LE_AUTO_SIG = signed(NEW_LE_AUTO, PRIVATE_KEY)

        with ephemeral_dir() as venv_dir:
            with server({'': """<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href="letsencrypt/">letsencrypt/</a>
</ul>
<hr>
</body>
</html>""",  # TODO: Cut this down.
                         'letsencrypt/json': dumps({'releases': {'99.9.9': None}}),
                         '99.9.9/letsencrypt-auto': NEW_LE_AUTO
                         '99.9.9/letsencrypt-auto.sig': NEW_LE_AUTO_SIG}) as base_url:
                # We need to serve a PyPI page that says a higher version.
                # We need to serve a newer le-auto.
                # And a sig.
            # Test when a phase-1 upgrade is needed, there's no LE binary
            # installed, and peep verifies:
            out, err = self.run_le_auto(venv_dir, base_url)


    # This conveniently sets us up to test the next 2 cases:
    # Test when no phase-1 upgrade is needed and no LE upgrade is needed (probably a common case).

    # Test (when no phase-1 upgrade is needed), there's an out-of-date LE script installed, (and peep works).
    # Test when peep has a hash mismatch.
    # Test when the OpenSSL sig mismatches.

    def test_thing(self):
        environ['LE_AUTO_JSON_URL'] = self.server_url() + 'pypi.json'
        environ['LE_AUTO_DIR_TEMPLATE'] = '%s%%s/' % self.server_url()
        environ['XDG_DATA_HOME'] =

# The only thing I'm not sure how to do is get SUDO to pass uninteractively. We really need sudo only for bootstrapping. Maybe we can run it in a container that doesn't ask for a password for sudo.
Use SSL_CERT_FILE or something to point le-auto at our new CA.
