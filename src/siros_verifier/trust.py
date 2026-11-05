"""Optional per-document go-trust authorization using verifier-core's AuthZEN contract.

Local parsing/verification remains in mdoc.py. This module only builds the
issuer evidence request and delegates the trust decision to the configured PDP.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import unicodedata
from urllib.parse import urlsplit

import aiohttp
from asn1crypto import x509 as asn1_x509

from siros_verifier import mdoc

DEFAULT_MDOC_ISSUER_ROLE = "pid-provider"
PDP_BEARER_TOKEN_ENV = "SIROS_PDP_BEARER_TOKEN"
PDP_TIMEOUT_SECONDS = 10.0
MAX_PDP_RESPONSE_BYTES = 1024 * 1024


class TrustError(Exception):
    """Base class for authorization configuration, evidence, and transport failures."""


class TrustDenied(TrustError):
    """The PDP explicitly denied at least one document."""


class TrustUnavailable(TrustError):
    """The PDP could not provide a valid authorization decision."""


def validate_mdoc_issuer_role(role: str) -> None:
    if not role or role.strip() != role or any(unicodedata.category(char) == "Cc" for char in role):
        raise TrustError("invalid mdoc issuer role")


def _hash_issuer_id(leaf_der: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(leaf_der).digest()).rstrip(b"=").decode("ascii")
    return f"x509_hash:{digest}"


def mdoc_issuer_id(leaf_der: bytes) -> str:
    """Match verifier-core's ordered, SAN-only DER traversal and leaf-hash fallback."""
    try:
        certificate = asn1_x509.Certificate.load(leaf_der)
        extensions = certificate["tbs_certificate"]["extensions"]
    except (TypeError, ValueError):
        return _hash_issuer_id(leaf_der)

    for extension in extensions:
        if extension["extn_id"].dotted != "2.5.29.17":
            continue
        try:
            san = asn1_x509.GeneralNames.load(extension["extn_value"].contents)
        except (TypeError, ValueError):
            return _hash_issuer_id(leaf_der)

        dns_name: str | None = None
        for name in san:
            if name.name == "uniform_resource_identifier":
                value = name.native
                if value.startswith("http://"):
                    return "https://" + value.removeprefix("http://")
                if value.startswith("https://"):
                    return value
            elif name.name == "dns_name" and dns_name is None and not name.native.startswith("*."):
                dns_name = name.native
        if dns_name is not None:
            return f"https://{dns_name}"
    return _hash_issuer_id(leaf_der)


def build_authzen_request(doc: mdoc.ParsedDocument, role: str) -> dict:
    """Build exactly one verifier-core-compatible request for a verified document."""
    validate_mdoc_issuer_role(role)
    chain = doc.issuer_auth.x5chain_der if doc.issuer_auth else []
    if not chain:
        raise TrustError(f"document {doc.doc_type!r} has no issuer certificate chain")

    issuer_id = mdoc_issuer_id(chain[0])
    return {
        "subject": {"type": "key", "id": issuer_id},
        "resource": {
            "type": "x5c",
            "id": issuer_id,
            "key": [base64.b64encode(certificate).decode("ascii") for certificate in chain],
        },
        "action": {"name": role, "parameters": {"credential_types": [doc.doc_type]}},
    }


def _validate_pdp_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise TrustError("invalid PDP evaluation URL") from exc
    if not hostname or (
        parsed.scheme != "https"
        and not (parsed.scheme == "http" and hostname in {"127.0.0.1", "localhost", "::1"})
    ):
        raise TrustError("PDP evaluation URL must use HTTPS, except HTTP on an exact loopback host")


def _validate_bearer_token(token: str | None) -> None:
    if token is not None and any(ord(char) != 9 and not 32 <= ord(char) <= 126 for char in token):
        raise TrustError("invalid PDP bearer token")


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


async def evaluate_request(payload: dict, pdp_url: str, bearer_token: str | None) -> bool:
    """POST one AuthZEN request and return only an explicit JSON boolean decision."""
    _validate_pdp_url(pdp_url)
    _validate_bearer_token(bearer_token)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    timeout = aiohttp.ClientTimeout(total=PDP_TIMEOUT_SECONDS)

    try:
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.post(pdp_url, data=body, headers=headers, allow_redirects=False) as response,
        ):
            if not 200 <= response.status < 300:
                raise TrustUnavailable(f"PDP returned HTTP {response.status}")
            if response.content_length is not None and response.content_length > MAX_PDP_RESPONSE_BYTES:
                raise TrustUnavailable("PDP response exceeded 1 MiB")
            response_body = bytearray()
            while len(response_body) <= MAX_PDP_RESPONSE_BYTES:
                chunk = await response.content.read(min(65536, MAX_PDP_RESPONSE_BYTES + 1 - len(response_body)))
                if not chunk:
                    break
                response_body.extend(chunk)
    except TrustError:
        raise
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        raise TrustUnavailable("PDP request failed") from None

    if len(response_body) > MAX_PDP_RESPONSE_BYTES:
        raise TrustUnavailable("PDP response exceeded 1 MiB")

    try:
        decoded = json.loads(
            response_body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise TrustUnavailable("PDP returned malformed JSON") from None
    if not isinstance(decoded, dict) or "decision" not in decoded or type(decoded["decision"]) is not bool:
        raise TrustUnavailable("PDP response did not contain a boolean decision")
    return decoded["decision"]


async def authorize_documents(
    documents: list[mdoc.ParsedDocument], pdp_url: str, role: str, bearer_token: str | None = None
) -> None:
    """Require an explicit permit for every document; never cache or combine decisions."""
    for doc in documents:
        payload = build_authzen_request(doc, role)
        if not await evaluate_request(payload, pdp_url, bearer_token):
            raise TrustDenied(f"go-trust denied document {doc.doc_type!r}")
