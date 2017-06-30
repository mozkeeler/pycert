#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Reads a certificate specification from stdin or a file and outputs a
PKCS7 (CMS) message with the desire properties.

The input format is as follows:

hash:<hex string>
signer:
<pycert specification>

hash is the value that will be put in the messageDigest attribute in
each SignerInfo of the signerInfos field of the SignedData.
The certificate specification must come last.
"""

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import tag, univ
from pyasn1_modules import rfc2315, rfc2459
import StringIO
import base64
import pycert
import sys

class CMS(object):
    """Utility class for reading a CMS specification and
    generating a CMS message"""

    def __init__(self, paramStream):
        self.hash = '0fc0ffee'
        signerSpecification = StringIO.StringIO()
        readingSignerSpecification = False
        for line in paramStream.readlines():
            if readingSignerSpecification:
                print >>signerSpecification, line
            elif line.strip() == 'signer:':
                readingSignerSpecification = True
            elif line.startswith('hash:'):
                self.hash = line.strip()[len('hash:'):]
        self.signer = pycert.Certificate(signerSpecification)

    def toDER(self):
        contentInfo = rfc2315.ContentInfo()
        contentInfo['contentType'] = rfc2315.signedData

        signedData = rfc2315.SignedData()
        signedData['version'] = rfc2315.Version(1)

        digestAlgorithms = rfc2315.DigestAlgorithmIdentifiers()
        sha1 = rfc2459.AlgorithmIdentifier()
        sha1['algorithm'] = univ.ObjectIdentifier('1.3.14.3.2.26')
        sha1['parameters'] = univ.Null()
        digestAlgorithms[0] = sha1
        signedData['digestAlgorithms'] = digestAlgorithms

        dataContentInfo = rfc2315.ContentInfo()
        dataContentInfo['contentType'] = rfc2315.data
        signedData['contentInfo'] = dataContentInfo

        certificates = rfc2315.ExtendedCertificatesAndCertificates().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        extendedCertificateOrCertificate = rfc2315.ExtendedCertificateOrCertificate()
        certificate = decoder.decode(self.signer.toDER(),
            asn1Spec=rfc2459.Certificate())[0]
        extendedCertificateOrCertificate['certificate'] = certificate
        certificates[0] = extendedCertificateOrCertificate
        signedData['certificates'] = certificates

        signerInfos = rfc2315.SignerInfos()
        signerInfo = rfc2315.SignerInfo()
        signerInfo['version'] = 1
        issuerAndSerialNumber = rfc2315.IssuerAndSerialNumber()
        issuerAndSerialNumber['issuer'] = self.signer.getIssuer()
        issuerAndSerialNumber['serialNumber'] = certificate['tbsCertificate']['serialNumber']
        signerInfo['issuerAndSerialNumber'] = issuerAndSerialNumber
        signerInfo['digestAlgorithm'] = sha1
        rsa = rfc2459.AlgorithmIdentifier()
        rsa['algorithm'] = rfc2459.rsaEncryption
        rsa['parameters'] = univ.Null()
        authenticatedAttributes = rfc2315.Attributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        hashAttribute = rfc2315.Attribute()
        # PKCS#9 messageDigest
        hashAttribute['type'] = univ.ObjectIdentifier('1.2.840.113549.1.9.4')
        hashAttribute['values'] = univ.SetOf(rfc2459.AttributeValue())
        hashAttribute['values'][0] = univ.OctetString(self.hash)
        authenticatedAttributes[0] = hashAttribute
        signerInfo['authenticatedAttributes'] = authenticatedAttributes
        signerInfo['digestEncryptionAlgorithm'] = rsa
        signerInfo['encryptedDigest'] = univ.OctetString('signature goes here')
        signerInfos[0] = signerInfo
        signedData['signerInfos'] = signerInfos

        encoded = encoder.encode(signedData)
        anyTag = univ.Any(encoded).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

        contentInfo['content'] = anyTag
        return encoder.encode(contentInfo)

    def toPEM(self):
        output = '-----BEGIN PKCS7-----'
        der = self.toDER()
        b64 = base64.b64encode(der)
        while b64:
            output += '\n' + b64[:64]
            b64 = b64[64:]
        output += '\n-----END PKCS7-----'
        return output

# When run as a standalone program, this will read a specification from
# stdin and output the certificate as PEM to stdout.
if __name__ == '__main__':
    print CMS(sys.stdin).toPEM()
