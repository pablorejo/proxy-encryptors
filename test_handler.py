import os
import ssl
import unittest
from unittest.mock import patch

from handler import _build_ssl_context


class HandlerTLSConfigTest(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    def test_build_ssl_context_default(self) -> None:
        context = _build_ssl_context()
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            self.assertFalse(bool(context.verify_flags & ssl.VERIFY_X509_STRICT))

    @patch.dict(
        os.environ,
        {
            "ETSI014_INSECURE_SKIP_VERIFY": "true",
        },
        clear=True,
    )
    def test_build_ssl_context_insecure(self) -> None:
        context = _build_ssl_context()
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
