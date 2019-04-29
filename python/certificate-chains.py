#! /usr/bin/env python3

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

import os, sys
import pathlib
import mmap
import binascii
import datetime
import argparse

class ExtensionNotFound(Exception):
    pass

def load_certificate(crtfile):
    """
    load certificate into memory
    """

    with open(crtfile) as c:
        with mmap.mmap(c.fileno(), 0, mmap.MAP_PRIVATE) as cm:
            data = cm.read()

    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except:
        try:
            return x509.load_der_x509_certificate(data, default_backend())
        except:
            return None

def load_certificates(crtpath = '.'):
    """
    loads all certificates in _crtpath_
    currently, understands only PEM-encoded certificates
    """

    for dirpath, dirnames, filenames in os.walk(crtpath):
        if dirpath == crtpath:
            certificates = {os.path.join(dirpath, crt): load_certificate(os.path.join(dirpath, crt)) for crt in filenames if os.path.splitext(crt)[1] in ['.crt', '.pem']}
    return dict(filter(lambda item: item[1] is not None, certificates.items()))

def x509_extensions(X509):
    """
    find _oid_ in extensions
    """

    xts = {}
    for e in X509.extensions:
        xts[e.oid._name] = e.value
    return xts

def authority_key_identifier(extensions):
    kid = extensions.get('authorityKeyIdentifier', None)
    if kid is not None:
        return binascii.b2a_hex( kid.key_identifier ).decode()
    else:
        raise ExtensionNotFound('extension "authorityKeyIdentifier" not found')

def subject_key_identifier(extensions):
    kid = extensions.get('subjectKeyIdentifier', None)
    if kid is not None:
        return binascii.b2a_hex( kid.digest ).decode()
    else:
        raise ExtensionNotFound('extension "subjectKeyIdentifier" not found')

def dn(component):
    return '/'.join(map(lambda oid: "{}={}".format(oid.oid._name, oid.value), component))


def fingerprint(X509, digest = 'sha256'):
    hdigests = {}
    digests = {
        'md5':    hashes.MD5,
        'sha1':   hashes.SHA1,
        'sha256': hashes.SHA256,
        'sha384': hashes.SHA384,
        'sha512': hashes.SHA512,
    }

    def __fingerprint(X509, dgst):
        __digest = binascii.b2a_hex( X509.fingerprint( digests[dgst]() ) ).decode()
        return ':'.join(map(''.join, zip(*[iter(__digest)] *2)))

    if digest == 'all':
        for dgst in digests:
            k = ' '.join([dgst.upper(), 'fingerprint'])
            hdigests[k] = __fingerprint(X509, dgst)
    else:
        dgst = digests.get(digest, None)
        if dgst is not None:
            k = ' '.join([digest.upper(), 'fingerprint'])
            hdigests[k] = __fingerprint(X509, dgst)

    return hdigests

def info(X509, extensions = {}):
    crtinfo = dict()

    subject = dn(X509.subject)
    issuer  = dn(X509.issuer)

    def asn1datetime(ts):
        return ts.isoformat(' ')

    notafter  = asn1datetime( X509.not_valid_after )
    notbefore = asn1datetime( X509.not_valid_before )
    serial    = X509.serial_number

    crtinfo['subject']   = subject
    crtinfo['issuer']    = issuer
    crtinfo['notbefore'] = notbefore
    crtinfo['notafter']  = notafter
    crtinfo['serial']    = serial

    sanlist = []
    try:
        sanlist = extensions['subjectAltName']
    except:
        pass

    if sanlist:
        sandns  = sanlist.get_values_for_type(x509.DNSName)
        sanips  = sanlist.get_values_for_type(x509.IPAddress)

        if sandns:
            sandns = map(lambda item: "{}:{}".format("DNS", item), sandns)
        if sanips:
            sanips = map(lambda item: "{}:{}".format("IP", item), sanips)

        san     = ', '.join(list(sandns) + list(sanips))
        crtinfo['san'] = san

    return {**crtinfo, **fingerprint(X509, 'all')}

def chain(certfile, certificates):
    """
    find certificates to build the chain from/for
    """

    chained = []

    X509 = certificates[certfile]
    extensions = x509_extensions(X509)

    try:
        subjectKeyId   = subject_key_identifier(extensions)
    except ExtensionNotFound as e:
        #print("{}: {}".format(certfile, e))
        return False, chained

    try:
        authorityKeyId = authority_key_identifier(extensions)
    except ExtensionNotFound as e:
        authorityKeyId = subjectKeyId

    crtinfo = info(X509, extensions)

    chained.append({certfile: crtinfo})
    for _certfile in certificates:
        if _certfile == certfile:
            continue

        _X509 = certificates[_certfile]
        _extensions = x509_extensions(_X509)

        try:
            _subjectKeyId   = subject_key_identifier(_extensions)
        except ExtensionNotFound as e:
            #print("{}: {}".format(_certfile, e))
            continue

        try:
            _authorityKeyId = authority_key_identifier(_extensions)
        except ExtensionNotFound as e:
            _authorityKeyId = _subjectKeyId

        crtinfo = info(_X509, _extensions)
        if authorityKeyId == _subjectKeyId:
            authorityKeyId = _authorityKeyId
            chained.append({_certfile: crtinfo})

            if _authorityKeyId == _subjectKeyId:
                return True, chained

    print("!!! WARNING: Incomplete chain !!!")
    return False, chained

def dump_certificate(outfile, complete, chained = []):
    for crtinfo in chained:
        for crt, _info in crtinfo.items():
            s_crtinfo = '\n'.join("# {:>24}: {}".format(k, v) for (k,v) in _info.items())

            with open(crt) as _crt_in:
                basename = os.path.basename(crt)
                if outfile is not sys.stdout:
                    with open(outfile, 'a') as _crt_out:
                        _crt_out.write("# {}\n".format(basename))
                        _crt_out.write("{}\n".format(s_crtinfo))
                        _crt_out.write( _crt_in.read() )
                else:
                    sys.stdout.write("# {}\n".format(basename))
                    sys.stdout.write("{}\n".format(s_crtinfo))
                    sys.stdout.write( _crt_in.read() )
    if not complete:
        print("!!! WARNING: Incomplete chain !!!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="build chain of certificates")

    parser.add_argument('-p', '--crtpath', required=True,  help='directory of certificates')
    parser.add_argument('-i', '--infile',  required=False,  help='certificate to build the chain to')
    parser.add_argument('-o', '--outfile', required=False, help='file to write chain to')
    parser.add_argument('-P', '--chainpath', required=False, help='path to save chains')
    args = parser.parse_args()

    crtpath = args.crtpath
    crtfile = args.infile
    outfile = args.outfile or sys.stdout

    certificates = load_certificates(crtpath = crtpath)

    if crtfile:
        complete, chained = chain(os.path.join(crtpath, crtfile), certificates)
        dump_certificate(outfile, complete, chained)
    else:
        for crt, _info in certificates.items():
            complete, chained = chain(crt, certificates)
            dump_certificate(outfile, complete, chained)

    sys.exit(0)
