# -*- coding: utf-8 -*-
"""TLS tests
"""
from __future__ import unicode_literals

import os
import socket
import unittest

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

# import the plain C wrapper module
import _ldap
from slapdtest import SlapdTestCase, requires_tls


class TestTLSLDAP(SlapdTestCase):

    @requires_tls()
    def test_tls_check_san(self):
        _ldap.set_option(_ldap.OPT_DEBUG_LEVEL, 255)
        # SAN entries
        self._check_hostname_match("server-san.python-ldap.test")
        self._check_hostname_match("localhost.localdomain")
        self._check_hostname_match("127.0.0.1")
        self._check_hostname_match("[::1]")

    @requires_tls()
    def test_tls_check_cn(self):
        # CN must not match
        # see https://tools.ietf.org/html/rfc6125#section-6.4.4
        # As noted, a client MUST NOT seek a match for a reference identifier
        # of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
        # URI-ID, or any application-specific identifier types supported by
        # the client.
        with self.assertRaises(_ldap.CONNECT_ERROR) as e:
            self._check_hostname_match("server-cn.python-ldap.test")
        self.assertIn("hostname does not match", str(e.exception))

    @requires_tls()
    def test_tls_check_mismatch(self):
        with self.assertRaises(_ldap.CONNECT_ERROR) as e:
            self._check_hostname_match("localhost.invalid")
        self.assertIn("hostname does not match", str(e.exception))

    def _check_hostname_match(self, hostname):
        uri = "ldap://{}".format(hostname)
        sock = socket.create_connection(
            (self.server.hostname, self.server.port)
        )
        try:
            l = _ldap.initialize_fd(sock.fileno(), uri)
            l.set_option(_ldap.OPT_HOST_NAME, hostname)
            l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
            l.set_option(_ldap.OPT_X_TLS_CACERTFILE, self.server.cafile)
            l.set_option(_ldap.OPT_X_TLS_CERTFILE, self.server.clientcert)
            l.set_option(_ldap.OPT_X_TLS_KEYFILE, self.server.clientkey)
            l.set_option(_ldap.OPT_X_TLS_REQUIRE_CERT, _ldap.OPT_X_TLS_HARD)
            l.set_option(_ldap.OPT_X_TLS_NEWCTX, 0)
            l.start_tls_s()
        finally:
            sock.close()

if __name__ == '__main__':
    unittest.main()
