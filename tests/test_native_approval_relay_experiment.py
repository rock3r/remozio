import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-native-approval-relay-experiment.py"
SPEC = importlib.util.spec_from_file_location("native_relay_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


class ExtensionUpgradeTests(unittest.TestCase):
    def test_rejected_extension_offer_cannot_produce_passing_evidence(self):
        class RejectedSocket:
            def __init__(self):
                self.response = io.BytesIO(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                self.request = b""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def sendall(self, data):
                self.request += data

            def recv(self, count):
                return self.response.read(count)

        sock = RejectedSocket()
        with patch.object(EXPERIMENT, "Probe") as probe:
            probe.return_value.connect.return_value = sock
            with self.assertRaisesRegex(RuntimeError, "Valid upgrade refused"):
                EXPERIMENT.framing(Path("/unused"), "extensionsNotNegotiated")
            self.assertIn(b"Sec-WebSocket-Extensions: permessage-deflate\r\n", sock.request)
            probe.return_value.close.assert_called_once()
