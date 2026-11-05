from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from siros_verifier import display, mdoc, trust

DOC_TYPE = "org.iso.18013.5.1.mDL"


def make_certificate(general_names=(), *, basic_constraints=False) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trust Test")])
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if general_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(general_names)), critical=False)
    if basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def make_document(chain=None) -> mdoc.ParsedDocument:
    chain = chain or [make_certificate()]
    issuer_auth = mdoc.IssuerAuthInfo(alg=-7, alg_name="ES256", x5chain_der=chain)
    return mdoc.ParsedDocument(
        doc_type=DOC_TYPE,
        namespaces={},
        issuer_auth=issuer_auth,
        device_namespaces={},
        device_auth_type=None,
        errors={},
    )


def evaluate(payload, url, token=None):
    return asyncio.run(trust.evaluate_request(payload, url, token))


def rewrite_san(der, rewrite):
    certificate = asn1_x509.Certificate.load(der)
    for extension in certificate["tbs_certificate"]["extensions"]:
        if extension["extn_id"].dotted == "2.5.29.17":
            old_value = extension["extn_value"]
            extension["extn_value"] = old_value.__class__(rewrite(old_value.contents))
    return certificate.dump()


def expected_hash_identity(der):
    digest = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
    return f"x509_hash:{digest}"


def test_issuer_id_prefers_uri_san_over_dns():
    der = make_certificate(
        [x509.DNSName("dns.example"), x509.UniformResourceIdentifier("https://issuer.example/path")]
    )
    assert trust.mdoc_issuer_id(der) == "https://issuer.example/path"


def test_issuer_id_converts_http_uri_to_https():
    der = make_certificate([x509.UniformResourceIdentifier("http://issuer.example:8080/path?q=1")])
    assert trust.mdoc_issuer_id(der) == "https://issuer.example:8080/path?q=1"


def test_issuer_id_uses_first_non_wildcard_dns_san():
    der = make_certificate([x509.DNSName("*.example"), x509.DNSName("issuer.example")])
    assert trust.mdoc_issuer_id(der) == "https://issuer.example"


def test_issuer_id_ignores_unrelated_malformed_extensions():
    der = make_certificate(
        [x509.UniformResourceIdentifier("https://issuer.example")], basic_constraints=True
    )
    certificate = asn1_x509.Certificate.load(der)
    for extension in certificate["tbs_certificate"]["extensions"]:
        if extension["extn_id"].dotted == "2.5.29.19":
            old_value = extension["extn_value"]
            extension["extn_value"] = old_value.__class__(b"\x30\x01\x01")
    malformed = certificate.dump()
    reloaded = asn1_x509.Certificate.load(malformed)
    basic_constraints = next(
        extension for extension in reloaded["tbs_certificate"]["extensions"] if extension["extn_id"].dotted == "2.5.29.19"
    )
    assert basic_constraints["extn_value"].contents == b"\x30\x01\x01"
    assert trust.mdoc_issuer_id(malformed) == "https://issuer.example"


def test_issuer_id_returns_first_usable_san_before_duplicate():
    der = make_certificate([x509.UniformResourceIdentifier("https://issuer.example")])
    certificate = asn1_x509.Certificate.load(der)
    san = certificate["tbs_certificate"]["extensions"][0]
    certificate["tbs_certificate"]["extensions"].append(san.copy())

    assert trust.mdoc_issuer_id(certificate.dump()) == "https://issuer.example"


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda san: san + b"\x00",
        lambda san: b"\x30\x80" + san[2:] + b"\x00\x00",
        lambda san: b"\x30\x81" + san[1:],
    ],
    ids=["trailing-data", "indefinite-length", "non-minimal-length"],
)
def test_issuer_id_rejects_non_der_san(rewrite):
    der = make_certificate([x509.UniformResourceIdentifier("https://issuer.example")])
    malformed = rewrite_san(der, rewrite)
    assert trust.mdoc_issuer_id(malformed) == expected_hash_identity(malformed)


@pytest.mark.parametrize(
    ("general_name", "ascii_value"),
    [
        (x509.UniformResourceIdentifier("https://issuer.example"), b"https://issuer.example"),
        (x509.DNSName("issuer.example"), b"issuer.example"),
    ],
    ids=["uri", "dns"],
)
def test_issuer_id_rejects_non_ia5_san_values(general_name, ascii_value):
    der = make_certificate([general_name])
    malformed = rewrite_san(der, lambda san: san.replace(ascii_value, ascii_value[:-1] + b"\xff"))
    assert trust.mdoc_issuer_id(malformed) == expected_hash_identity(malformed)


def test_issuer_id_hashes_exact_leaf_when_no_usable_san():
    der = make_certificate([x509.DNSName("*.example"), x509.UniformResourceIdentifier("did:example:issuer")])
    expected = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
    assert trust.mdoc_issuer_id(der) == f"x509_hash:{expected}"


def test_authzen_request_matches_verifier_core_shape_and_chain_order():
    leaf = make_certificate([x509.DNSName("issuer.example")])
    intermediate = make_certificate()
    request = trust.build_authzen_request(make_document([leaf, intermediate]), "pid-provider")

    assert request == {
        "subject": {"type": "key", "id": "https://issuer.example"},
        "resource": {
            "type": "x5c",
            "id": "https://issuer.example",
            "key": [base64.b64encode(leaf).decode(), base64.b64encode(intermediate).decode()],
        },
        "action": {"name": "pid-provider", "parameters": {"credential_types": [DOC_TYPE]}},
    }
    assert "context" not in request


def test_raw_chain_is_not_added_to_display_json():
    assert "x5chain_der" not in display.to_jsonable(make_document().issuer_auth)


@pytest.mark.parametrize("role", ["", " pid-provider", "pid-provider ", "pid\nprovider", "pid\x80provider", "pid\x85provider", "pid\x9fprovider"])
def test_authzen_request_rejects_invalid_role(role):
    with pytest.raises(trust.TrustError, match="invalid mdoc issuer role"):
        trust.build_authzen_request(make_document(), role)


class PDPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append({"path": self.path, "headers": self.headers, "body": body})
        status, response_body, headers = self.server.responses.pop(0)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        drip_delay = getattr(self.server, "drip_delay", 0)
        try:
            if drip_delay:
                for byte in response_body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(drip_delay)
            else:
                self.wfile.write(response_body)
        except BrokenPipeError:
            pass

    def log_message(self, *args):
        pass


@pytest.fixture
def pdp_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), PDPHandler)
    server.requests = []
    server.responses = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_port}/evaluation"
    server.shutdown()
    thread.join()
    server.server_close()


def queue_response(server, body=b'{"decision":true}', status=200, headers=None):
    server.responses.append((status, body, headers or {}))


def test_evaluation_posts_exact_request_and_bearer(pdp_server):
    server, url = pdp_server
    queue_response(server)
    payload = trust.build_authzen_request(make_document(), "pid-provider")

    assert evaluate(payload, url, "secret-token") is True
    assert len(server.requests) == 1
    captured = server.requests[0]
    assert captured["path"] == "/evaluation"
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert json.loads(captured["body"]) == payload


def test_evaluation_accepts_explicit_false_as_denial(pdp_server):
    server, url = pdp_server
    queue_response(server, b'{"decision":false}')
    assert evaluate({}, url, None) is False


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b'{"decision":"true"}',
        b'{"decision":1}',
        b'{"decision":null}',
        b'{"decision":true,"decision":true}',
        b'{"decision":true} trailing',
        b'{"decision":NaN}',
        b"\xff",
    ],
)
def test_evaluation_rejects_malformed_decisions(pdp_server, body):
    server, url = pdp_server
    queue_response(server, body)
    with pytest.raises(trust.TrustUnavailable):
        evaluate({}, url, None)


def test_evaluation_rejects_http_error(pdp_server):
    server, url = pdp_server
    queue_response(server, status=503)
    with pytest.raises(trust.TrustUnavailable, match="HTTP 503"):
        evaluate({}, url, None)


def test_evaluation_does_not_follow_redirects(pdp_server):
    server, url = pdp_server
    queue_response(server, status=302, headers={"Location": "/elsewhere"})
    with pytest.raises(trust.TrustUnavailable, match="HTTP 302"):
        evaluate({}, url, None)
    assert len(server.requests) == 1


def test_evaluation_rejects_oversized_response(pdp_server):
    server, url = pdp_server
    queue_response(server, b" " * (trust.MAX_PDP_RESPONSE_BYTES + 1))
    with pytest.raises(trust.TrustUnavailable, match="1 MiB"):
        evaluate({}, url, None)


def test_evaluation_total_timeout_includes_slow_body_delivery(pdp_server, monkeypatch):
    server, url = pdp_server
    server.drip_delay = 0.02
    monkeypatch.setattr(trust, "PDP_TIMEOUT_SECONDS", 0.05)
    queue_response(server)

    with pytest.raises(trust.TrustUnavailable, match="request failed"):
        evaluate({}, url, None)


def test_evaluation_rejects_malformed_bearer_without_disclosure():
    secret = "bad\nSECRET-TOKEN"
    with pytest.raises(trust.TrustError) as error:
        evaluate({}, "https://pdp.example/evaluation", secret)
    assert "invalid PDP bearer token" in str(error.value)
    assert "SECRET-TOKEN" not in str(error.value)


def test_evaluation_requires_https_except_loopback():
    with pytest.raises(trust.TrustError, match="HTTPS"):
        evaluate({}, "http://pdp.example/evaluation", None)


def test_every_document_requires_a_permit(pdp_server):
    server, url = pdp_server
    queue_response(server, b'{"decision":true}')
    queue_response(server, b'{"decision":false}')
    documents = [make_document(), make_document()]

    with pytest.raises(trust.TrustDenied):
        asyncio.run(trust.authorize_documents(documents, url, "pid-provider"))
    assert len(server.requests) == 2
