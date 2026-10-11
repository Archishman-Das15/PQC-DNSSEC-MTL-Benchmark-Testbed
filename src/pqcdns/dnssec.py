"""
DNSSEC primitives shared by the signer and the validator.

  KSK : ECDSAP256SHA256 (alg 13, classical)  -> signs the DNSKEY RRset only
  ZSK : ML-DSA-44            (lab alg 200)    -> signs every other authoritative RRset
     or ML-DSA-44-MTL-SHAKE-128 (lab alg 201)

Algorithm numbers 200/201 are LAB-ONLY placeholders (IANA has assigned none; the
Verisign DNSSEC draft lists them as TBD).  Change them here only.
"""
from __future__ import annotations

import struct

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

ALG_ECDSAP256 = 13
ALG_MLDSA44 = 200
ALG_MLDSA44_MTL = 201
PQC_ALGS = {ALG_MLDSA44: "ML-DSA-44", ALG_MLDSA44_MTL: "ML-DSA-44-MTL-SHAKE-128"}
MODE_TO_ALG = {"mldsa44": ALG_MLDSA44, "mtl": ALG_MLDSA44_MTL}

MLDSA_NAME = "ML-DSA-44"
LADDER_LABEL = "_mtlladder"   # well-known owner name that serves the FULL MTL signature


# ------------------------------------------------------------------ ML-DSA-44 (liboqs)
class MLDSA44:
    def __init__(self, public_key: bytes | None = None, secret_key: bytes | None = None):
        self.sig = oqs.Signature(MLDSA_NAME, secret_key)
        self.pk = public_key
        if secret_key is None and public_key is None:
            self.pk = self.sig.generate_keypair()
            self.sk = self.sig.export_secret_key()
        else:
            self.sk = secret_key

    def sign(self, msg: bytes, ctx: bytes = b"") -> bytes:
        return self.sig.sign_with_ctx_str(msg, ctx)

    @staticmethod
    def verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        with oqs.Signature(MLDSA_NAME) as v:
            return v.verify_with_ctx_str(msg, sig, ctx, pk)


class MLDSAVerifier:
    """Reusable verifier object (avoids per-call liboqs object setup in hot loops)."""
    def __init__(self):
        self.v = oqs.Signature(MLDSA_NAME)

    def verify(self, pk, msg, sig, ctx=b""):
        return self.v.verify_with_ctx_str(msg, sig, ctx, pk)


# ------------------------------------------------------------------ ECDSA P-256 (RFC 6605)
def ecdsa_pub_to_dnskey(pub: ec.EllipticCurvePublicKey) -> bytes:
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def ecdsa_dnskey_to_pub(key: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicNumbers(int.from_bytes(key[:32], "big"),
                                         int.from_bytes(key[32:], "big"),
                                         ec.SECP256R1()).public_key()


def ecdsa_sign(priv, data: bytes) -> bytes:
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ecdsa_verify(key: bytes, data: bytes, sig: bytes) -> bool:
    try:
        ecdsa_dnskey_to_pub(key).verify(
            encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
            data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ RFC 4034 3.1.8.1 signing data
def rrsig_header_wire(type_covered, alg, labels, orig_ttl, expiration, inception, key_tag,
                      signer: dns.name.Name) -> bytes:
    return struct.pack(">HBBIIIH", type_covered, alg, labels, orig_ttl, expiration,
                       inception, key_tag) + signer.canonicalize().to_wire()


def canonical_rrset_wire(rrset: dns.rrset.RRset, orig_ttl: int) -> bytes:
    owner = rrset.name.canonicalize().to_wire()
    rdatas = sorted(rd.to_digestable(dns.name.root) for rd in rrset)
    out = []
    prev = None
    for rd in rdatas:
        if rd == prev:          # duplicate RRs are suppressed in canonical form
            continue
        prev = rd
        out.append(owner + struct.pack(">HHIH", rrset.rdtype, rrset.rdclass, orig_ttl, len(rd)) + rd)
    return b"".join(out)


def signing_data(rrset, type_covered, alg, labels, orig_ttl, expiration, inception, key_tag,
                 signer) -> bytes:
    return rrsig_header_wire(type_covered, alg, labels, orig_ttl, expiration, inception,
                             key_tag, signer) + canonical_rrset_wire(rrset, orig_ttl)


def signing_data_from_rrsig(rrset, rrsig) -> bytes:
    return signing_data(rrset, rrsig.type_covered, rrsig.algorithm, rrsig.labels,
                        rrsig.original_ttl, rrsig.expiration, rrsig.inception,
                        rrsig.key_tag, rrsig.signer)


def label_count(name: dns.name.Name) -> int:
    n = len(name.labels) - 1                 # drop root label
    if n > 0 and name.labels[0] == b"*":
        n -= 1
    return n


def make_rrsig(type_covered, alg, labels, orig_ttl, expiration, inception, key_tag, signer, sig):
    w = rrsig_header_wire(type_covered, alg, labels, orig_ttl, expiration, inception,
                          key_tag, signer) + sig
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.RRSIG, w, 0, len(w))


def make_dnskey(flags: int, alg: int, key: bytes):
    w = struct.pack(">HBB", flags, 3, alg) + key
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DNSKEY, w, 0, len(w))


def key_tag(dnskey) -> int:
    return dns.dnssec.key_id(dnskey)
