
import socket
import unittest

from scanner.port_scanner import (
    validate_target,
    validate_ports,
    identify_service,
    scan_port
)


class TestPortScanner(unittest.TestCase):

    def test_valid_target(self):

        self.assertTrue(
            validate_target("127.0.0.1")
        )

    def test_invalid_target(self):

        self.assertFalse(
            validate_target("invalid-host-name-xyz")
        )

    def test_valid_ports(self):

        self.assertTrue(
            validate_ports(1, 100)
        )

    def test_invalid_port(self):

        self.assertFalse(
            validate_ports(0, 100)
        )

    def test_invalid_range(self):

        self.assertFalse(
            validate_ports(500, 100)
        )

    def test_ssh_service(self):

        self.assertEqual(
            identify_service(22), "SSH"
        )

    def test_http_service(self):

        self.assertEqual(
            identify_service(80), "HTTP"
        )

    def test_https_service(self):

        self.assertEqual(
            identify_service(443), "HTTPS"
        )

    def test_open_port(self):

        server = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server.bind(("127.0.0.1", 0))
        server.listen(1)

        port = server.getsockname()[1]

        try:

            result = scan_port("127.0.0.1", port)

            self.assertTrue(result)

        finally:
            server.close()

    def test_closed_port(self):

        server = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server.bind(("127.0.0.1", 0))

        port = server.getsockname()[1]

        server.close()

        result = scan_port("127.0.0.1", port)

        self.assertFalse(result)


if __name__ == "__main__":

    unittest.main(verbosity=2)

