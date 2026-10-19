import io
import unittest
import urllib.error
from unittest.mock import patch

from provider_client import PreparedRequest
from provider_transport import MAX_RESPONSE_BYTES, ProviderTransportError, _NoRedirect, send_prepared_request


class _Response:
    def __init__(self, body, content_type="application/json"):
        self._body = body.encode()
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]


class ProviderTransportTests(unittest.TestCase):
    def setUp(self):
        self.request = PreparedRequest(
            "https://api.example.test/v1/chat/completions",
            {"Authorization": "Bearer secret"},
            b"{}",
        )

    @patch("provider_transport.urllib.request.build_opener")
    def test_reads_json_response(self, build_opener):
        build_opener.return_value.open.return_value = _Response(
            '{"choices":[{"message":{"content":"answer"}}]}'
        )
        self.assertEqual(send_prepared_request(self.request, 30), "answer")

    @patch("provider_transport.urllib.request.build_opener")
    def test_reads_streaming_response(self, build_opener):
        build_opener.return_value.open.return_value = _Response(
            'data: {"choices":[{"delta":{"content":"hel"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
            "data: [DONE]\n",
            "text/event-stream",
        )
        self.assertEqual(send_prepared_request(self.request, 30), "hello")

    @patch("provider_transport.urllib.request.build_opener")
    def test_rejects_oversized_response(self, build_opener):
        build_opener.return_value.open.return_value = _Response("x" * (MAX_RESPONSE_BYTES + 1))
        with self.assertRaisesRegex(ProviderTransportError,"4 MiB"):
            send_prepared_request(self.request,30)

    @patch("provider_transport.urllib.request.build_opener")
    def test_http_error_does_not_expose_provider_body_or_key(self, build_opener):
        build_opener.return_value.open.side_effect = urllib.error.HTTPError(
            self.request.url,401,"unauthorized",{},io.BytesIO(b"echoed secret Bearer secret")
        )
        with self.assertRaises(ProviderTransportError) as raised:
            send_prepared_request(self.request,30)
        self.assertEqual(str(raised.exception),"provider returned HTTP 401")
        self.assertNotIn("secret",str(raised.exception))

    def test_redirect_handler_refuses_redirect(self):
        handler=_NoRedirect()
        request=__import__("urllib.request").request.Request(self.request.url)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            handler.redirect_request(request,None,302,"Found",{},"https://other.example/")
        raised.exception.close()


if __name__ == "__main__":
    unittest.main()
