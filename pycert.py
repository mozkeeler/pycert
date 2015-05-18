#!/usr/bin/python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# The input format is as follows:
#
# version:<v1|v2|v3>
# signature:<(sha256|sha1|md5|md2)WithRSAEncryption>
# issuer:<stringified DN of the form /C=XX/O=Example Organization/CN=...>
# notBefore:<string describing time relative to now>
# notAfter:<string describing time relative to now>
# subject:<stringified DN of the form /C=XX/O=Example Organization/CN=...>
# subjectPublicKey:<string describing spki>
# issuerPublicKey:<string describing spki>
# signatureAlgorithm:<(sha256|sha1|md5|md2)WithRSAEncryption>
# [extension:<extension name:<extension-specific data>>]
# [...]
#
# Known extensions are:
# basicConstraints:[cA],[pathLenConstraint]
# keyUsage:[digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,
#           keyAgreement,keyCertSign,cRLSign]
# extKeyUsage:[serverAuth,clientAuth]
#
# Most fields have a default value. The only required fields are issuer and
# subject.


import base64
import datetime
import random
import sys
from pyasn1.codec.der import encoder
from pyasn1.codec.der import decoder
from pyasn1.type import namedtype, tag, univ, useful
from pyasn1_modules import rfc2459

def sufficientlyUniqueSerialNumber():
    serialBytes = [random.randint(0, 255) for i in range(20)]
    # Ensure that the most significant bit isn't set (which would indicate a
    # negative number, which isn't valid for serial numbers).
    serialBytes[0] &= 0x7f 
    # Also ensure that the least significant bit on the most significant byte
    # is set (to prevent a leading zero byte, which also wouldn't be valid).
    serialBytes[0] |= 0x01
    # Now prepend the ASN.1 INTEGER tag and length bytes.
    serialBytes.insert(0, len(serialBytes))
    serialBytes.insert(0, getASN1Tag(univ.Integer))
    return ''.join(map(lambda b : chr(b), serialBytes))

def getASN1Tag(asn1Type):
    return asn1Type.baseTagSet.getBaseTag().asTuple()[2]

def stringToAlgorithmIdentifier(string):
    algorithmIdentifier = rfc2459.AlgorithmIdentifier()
    algorithm = None
    if string == "sha256WithRSAEncryption":
        algorithm = univ.ObjectIdentifier('1.2.840.11359.1.1.11')
    # do more of these...
    if algorithm == None:
        raise Exception("unknown signature type '%s'" % string)
    algorithmIdentifier.setComponentByName('algorithm', algorithm)
    return algorithmIdentifier

def stringToCommonName(string):
    ava = rfc2459.AttributeTypeAndValue()
    ava.setComponentByName('type', rfc2459.id_at_commonName)
    ava.setComponentByName('value', rfc2459.X520CommonName(string))
    rdn = rfc2459.RelativeDistinguishedName()
    rdn.setComponentByPosition(0, ava)
    rdns = rfc2459.RDNSequence()
    rdns.setComponentByPosition(0, rdn)
    name = rfc2459.Name()
    name.setComponentByPosition(0, rdns)
    return name

def datetimeToTime(datetime):
    time = rfc2459.Time()
    time.setComponentByName('generalTime', useful.GeneralizedTime(datetime.strftime("%Y%m%d%H%M%SZ")))
    return time

def byteToHex(b):
    h = hex(ord(b))[2:]
    if len(h) == 1: return '0' + h
    return h

class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('N', univ.Integer()),
        namedtype.NamedType('E', univ.Integer()))

class CertificateParameters:
    
    sharedRSA_N = int("00ba8851a8448e16d641fd6eb6880636103d3c13d9eae4354ab4ecf56857" + \
                      "6c247bc1c725a8e0d81fbdb19c069b6e1a86f26be2af5a756b6a6471087a" + \
                      "a55aa74587f71cd5249c027ecd43fc1e69d038202993ab20c349e4dbb94c" + \
                      "c26b6c0eed15820ff17ead691ab1d3023a8b2a41eea770e00f0d8dfd660b" + \
                      "2bb02492a47db988617990b157903dd23bc5e0b8481fa837d38843ef2716" + \
                      "d855b7665aaa7e02902f3a7b10800624cc1c6c97ad96615bb7e29612c075" + \
                      "31a30c91ddb4caf7fcad1d25d309efb9170ea768e1b37b2f226f69e3b48a" + \
                      "95611dee26d6259dab91084e36cb1c24042cbf168b2fe5f18f991731b8b3" + \
                      "fe4923fa7251c431d503acda180a35ed8d", 16)
    sharedRSA_E = 65537

    def __init__(self):
        self.serialNumber = sufficientlyUniqueSerialNumber()
        self.version = "v3"
        self.signature = "sha256WithRSAEncryption"
        self.issuer = "Default Issuer"
        self.notBefore = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        self.notAfter = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        self.subject = "Default Subject"
        self.signatureAlgorithm = "sha256WithRSAEncryption"
        self.extensions = None

    def getVersion(self):
        return rfc2459.Version(self.version).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    def getSerialNumber(self):
        return decoder.decode(self.serialNumber)[0]

    def getSignature(self):
        return stringToAlgorithmIdentifier(self.signature)

    def getIssuer(self):
        return stringToCommonName(self.issuer)

    def getValidity(self):
        validity = rfc2459.Validity()
        validity.setComponentByName('notBefore', self.getNotBefore())
        validity.setComponentByName('notAfter', self.getNotAfter())
        return validity

    def getNotBefore(self):
        return datetimeToTime(self.notBefore)

    def getNotAfter(self):
        return datetimeToTime(self.notAfter)

    def getSubject(self):
        return stringToCommonName(self.subject)

    def getSignatureAlgorithm(self):
        return stringToAlgorithmIdentifier(self.signature)

    def getSubjectPublicKey(self):
        rsaKey = RSAPublicKey()
        rsaKey.setComponentByName('N', univ.Integer(self.sharedRSA_N))
        rsaKey.setComponentByName('E', univ.Integer(self.sharedRSA_E))
        hexString = "".join([byteToHex(b) for b in encoder.encode(rsaKey)])
        return univ.BitString("'%s'H" % hexString)

    def getSubjectPublicKeyInfo(self):
        spki = rfc2459.SubjectPublicKeyInfo()
        spki.setComponentByName('algorithm', self.getSignatureAlgorithm())
        spki.setComponentByName('subjectPublicKey', self.getSubjectPublicKey())
        return spki

    def toDER(self):
        tbsCertificate = rfc2459.TBSCertificate()
        tbsCertificate.setComponentByName('version', self.getVersion())
        tbsCertificate.setComponentByName('serialNumber', self.getSerialNumber())
        tbsCertificate.setComponentByName('signature', self.getSignature())
        tbsCertificate.setComponentByName('issuer', self.getIssuer())
        tbsCertificate.setComponentByName('validity', self.getValidity())
        tbsCertificate.setComponentByName('subject', self.getSubject())
        tbsCertificate.setComponentByName('subjectPublicKeyInfo', self.getSubjectPublicKeyInfo())
        der = encoder.encode(tbsCertificate)
        print base64.b64encode(der)
        return der

if __name__ == "__main__":
    certificate = CertificateParameters()
    der = certificate.toDER()
