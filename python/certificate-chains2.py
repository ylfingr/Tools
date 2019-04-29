#! /usr/bin/env python3

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

import sys
import mmap
import binascii

cert = None

if cert is None:
    # meaningful error message
    sys.exit(1)

with open(cert) as c:
    with mmap.mmap(c.fileno(), 0, mmap.MAP_PRIVATE) as cm:
            data = cm.read()

crt = x509.load_pem_x509_certificate(data, default_backend())
print(crt.version)
fp = crt.fingerprint(hashes.SHA256())
print( binascii.b2a_hex(fp).decode())

print( crt.not_valid_before )

attributes = [
    "OID_COMMON_NAME",
    "OID_COUNTRY_NAME",
    "OID_DOMAIN_COMPONENT",
    "OID_DN_QUALIFIER",
    "OID_EMAIL_ADDRESS",
    "OID_GENERATION_QUALIFIER",
    "OID_GIVEN_NAME",
    "OID_LOCALITY_NAME",
    "OID_ORGANIZATIONAL_UNIT_NAME",
    "OID_ORGANIZATION_NAME",
    "OID_PSEUDONYM",
    "OID_SERIAL_NUMBER",
    "OID_STATE_OR_PROVINCE_NAME",
    "OID_SURNAME",
    "OID_TITLE",
    ]

oidmap = {
    "OID_COMMON_NAME": "CN",
    "OID_COUNTRY_NAME": "C",
    "OID_DOMAIN_COMPONENT": "DC",
    "OID_DN_QUALIFIER": "DN",
    "OID_EMAIL_ADDRESS": "emailAddress",
    "OID_GENERATION_QUALIFIER": "generationQualifier",
    "OID_GIVEN_NAME": "givenName",
    "OID_LOCALITY_NAME": "L",
    "OID_ORGANIZATIONAL_UNIT_NAME": "OU",
    "OID_ORGANIZATION_NAME": "O",
    "OID_PSEUDONYM": "pseudonym",
    "OID_SERIAL_NUMBER": "serialNumber",
    "OID_STATE_OR_PROVINCE_NAME": "S",
    "OID_SURNAME": "surName",
    "OID_TITLE": "T",
}

s = []
for attr in attributes:
    oid = getattr(x509, attr)
    info = crt.subject.get_attributes_for_oid(oid)
    if info:
        print(attr, info[0]._oid._name, info[0]._value)
        s.append({oidmap[attr]: info[0].value})
print(s)

def subject(s):
    print(list(reversed(['{}={}'.format(k,v) for d in s for k,v in d.items()])))
subject(s)

def subject(crt):
    pass

print(x509)
print("Domain: {}".format('/'.join(map(lambda oid: "{}={}".format(oid.oid._name, oid.value), crt.subject))))
xts = {}
for e in crt.extensions:
    xts[e.oid._name] = e.value
print("extensions: ")
#print(xts['authorityKeyIdentifier'])
#print(xts['subjectKeyIdentifier'])
#print(xts['subjectAltName'])

a = xts['authorityKeyIdentifier']
print(binascii.b2a_hex(a.key_identifier).decode())
akid = crt.extensions.get_extension_for_oid(
    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
akid = binascii.b2a_hex(akid.value.key_identifier).decode()
print(akid)

b = xts['subjectKeyIdentifier']
skid = binascii.b2a_hex(b.digest).decode()
print(skid)
print(':'.join(map(''.join, zip(*[iter(skid)] *2))))
