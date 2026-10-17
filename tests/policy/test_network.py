import io
import socket
from unittest.mock import patch

import pytest

from traceguard.policy.network import (
    PublicHTTPTransport,
    UnsafeDestination,
    destination,
    public_addresses,
    target_within_scope,
)


@pytest.mark.parametrize(
    "target",
    [
        "https://allowed.test.evil.test/",
        "https://allowed.test@evil.test/",
        "https://allowed.test:444/",
        "http://allowed.test/",
        "https://allowed.test/../admin",
        "https://allowed.test/%2e%2e/admin",
        "https://allowed.test/%252e/admin",
        "https://allowed.test/public%2fadmin",
        "https://allowed.test./",
        "https://allowed.test/?leak=canary",
        "https://allowed.test/#fragment",
    ],
)
def test_url_aliases_and_ungranted_query_are_not_authorized(target):
    assert not target_within_scope("https://allowed.test/", target)


def test_origin_normalization_preserves_path_segment_scope():
    assert target_within_scope("https://ALLOWED.test:443/public", "https://allowed.test/public/a")
    assert not target_within_scope("https://allowed.test/public", "https://allowed.test/publicity")
    assert target_within_scope(
        "https://allowed.test/public?q=approved", "https://allowed.test/public/a?q=approved"
    )


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "::ffff:8.8.8.8"]
)
def test_non_public_and_mapped_addresses_fail_closed(address):
    with patch(
        "traceguard.policy.network.socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, 443))],
    ):
        with pytest.raises(UnsafeDestination):
            public_addresses("example.test", 443)


def test_mixed_dns_answers_are_denied():
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", (a, 443)) for a in ["8.8.8.8", "127.0.0.1"]
    ]
    with patch("traceguard.policy.network.socket.getaddrinfo", return_value=answers):
        with pytest.raises(UnsafeDestination):
            public_addresses("example.test", 443)


def test_redirect_is_not_followed_and_response_is_bounded():
    class Connection:
        calls = []
        status = 302

        def __init__(self, host, port, address, timeout):
            self.calls.append((host, address))

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return self

        def read(self, size):
            return io.BytesIO(b"x" * 8).read(size)

        def close(self):
            pass

    with (
        patch("traceguard.policy.network.public_addresses", return_value=("8.8.8.8",)),
        patch("traceguard.policy.network.PinnedHTTPSConnection", Connection),
    ):
        with pytest.raises(UnsafeDestination, match="redirects"):
            PublicHTTPTransport().request("GET", "https://allowed.test/", {}, None)
        assert Connection.calls == [("allowed.test", "8.8.8.8")]
        Connection.status = 200
        with pytest.raises(UnsafeDestination, match="exceeds"):
            PublicHTTPTransport().request("GET", "https://allowed.test/", {}, None, max_bytes=4)
        assert PublicHTTPTransport().request("GET", "https://allowed.test/", {}, None) == b"x" * 8


@pytest.mark.parametrize(
    "headers", [{"Host": "evil.test"}, {"X-Test": "a\r\nb"}, {"Transfer-Encoding": "chunked"}]
)
def test_headers_cannot_change_transport_authority(headers):
    with pytest.raises(UnsafeDestination):
        PublicHTTPTransport().request("GET", "https://allowed.test/", headers, None)


def test_userinfo_and_controls_rejected_before_transport():
    with pytest.raises(UnsafeDestination):
        destination("https://allowed.test\n.evil.test/")
