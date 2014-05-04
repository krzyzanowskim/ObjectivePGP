//
//  PGPTypes.h
//  PGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#ifndef OpenPGPKeyring_PGPTypes_h
#define OpenPGPKeyring_PGPTypes_h

typedef NS_ENUM(NSInteger, PGPFormatType) {
    PGPFormatUnknown = 0,
    PGPFormatOld     = 1,
    PGPFormatNew     = 2
};

typedef NS_ENUM(NSUInteger, PGPHeaderPacketTag) {
    PGPHeaderPacketTagNewFormat  = 0x40,
    PGPHeaderPacketTagAllwaysSet = 0x80
};

typedef NS_ENUM(UInt8, PGPPacketTag) {
    PGPPublicKeyEncryptedSessionKeyPacketTag                 = 1,
    PGPSignaturePacketTag                                    = 2,
    PGPSymetricKeyEncryptedSessionKeyPacketTag               = 3,
    PGPOnePassSignaturePacketTag                             = 4,
    PGPSecretKeyPacketTag                                    = 5,
    PGPPublicKeyPacketTag                                    = 6,
    PGPSecretSubkeyPacketTag                                 = 7,
    PGPCompressedDataPacketTag                               = 8,
    PGPSymmetricallyEncryptedDataPacketTag                   = 9,
    PGPMarkerPacketTag                                       = 10,
    PGPLiteralDataPacketTag                                  = 11,
    PGPTrustPacketTag                                        = 12,
    PGPUserIDPacketTag                                       = 13,
    PGPPublicSubkeyPacketTag                                 = 14,
    PGPUserAttributePacketTag                                = 17,
    PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag = 18,
    PGPModificationDetectionCodePacket                       = 19,
};

typedef NS_ENUM(UInt8, PGPPublicKeyAlgorithm) {
    PGPPublicKeyAlgorithmRSA                = 1,
    PGPPublicKeyAlgorithmRSAEncryptOnly     = 2,
    PGPPublicKeyAlgorithmRSASignOnly        = 3,
    PGPPublicKeyAlgorithmElgamalEncryptOnly = 16,
    PGPPublicKeyAlgorithmDSA                = 17,
    PGPPublicKeyAlgorithmElliptic           = 18,
    PGPPublicKeyAlgorithmECDSA              = 19,
    PGPPublicKeyAlgorithmElgamal            = 20,
    PGPPublicKeyAlgorithmDiffieHellman      = 21,
    PGPPublicKeyAlgorithmPrivate1           = 100,
    PGPPublicKeyAlgorithmPrivate2           = 101,
    PGPPublicKeyAlgorithmPrivate3           = 102,
    PGPPublicKeyAlgorithmPrivate4           = 103,
    PGPPublicKeyAlgorithmPrivate5           = 104,
    PGPPublicKeyAlgorithmPrivate6           = 105,
    PGPPublicKeyAlgorithmPrivate7           = 106,
    PGPPublicKeyAlgorithmPrivate8           = 107,
    PGPPublicKeyAlgorithmPrivate9           = 108,
    PGPPublicKeyAlgorithmPrivate10          = 109,
    PGPPublicKeyAlgorithmPrivate11          = 110
};

typedef NS_ENUM(UInt8, PGPHashAlgorithm) {
    PGPHashMD5       = 1, //MD5  - deprecated
    PGPHashSHA1      = 2, //SHA1 - required
    PGPHashRIPEMD160 = 3, //RIPEMD160
    PGPHashSHA256    = 8, //SHA256
    PGPHashSHA384    = 9, //SHA384
    PGPHashSHA512    = 10,//SHA512
    PGPHashSHA224    = 11 //SHA224
};

typedef NS_ENUM(UInt8, PGPSignatureType) {
    PGPSignatureBinaryDocument                          = 0x00,
    PGPSignatureCanonicalTextDocument                   = 0x01,
    PGPSignatureStandalone                              = 0x02,
    PGPSignatureGenericCertificationUserIDandPublicKey  = 0x10,
    PGPSignaturePersonalCertificationUserIDandPublicKey = 0x11,
    PGPSignatureCasualCertificationUserIDandPublicKey   = 0x12,
    PGPSignaturePositiveCertificationUserIDandPublicKey = 0x13,
    PGPSignatureSubkeyBinding                           = 0x18,
    PGPSignaturePrimaryKeyBinding                       = 0x19,
    PGPSignatureDirectlyOnKey                           = 0x1F,
    PGPSignatureKeyRevocation                           = 0x20,
    PGPSignatureSubkeyRevocation                        = 0x28,
    PGPSignatureClarificationRecocation                 = 0x30,
    PGPSignatureTimestamp                               = 0x40,
    PGPSignature3PartyConfirmation                      = 0x50
};

typedef NS_ENUM(UInt8, PGPSignatureSubpacketType) {
    PGPSignatureSubpacketCreationTime                  = 2,
    PGPSignatureSubpacketExpirationTime                = 3,
    PGPSignatureSubpacketExportableCertification       = 4,
    PGPSignatureSubpacketTrustSignature                = 5,
    PGPSignatureSubpacketRegularExpression             = 6,
    PGPSignatureSubpacketRevocable                     = 7,
    PGPSignatureSubpacketKeyExpirationTime             = 9,
    PGPSignatureSubpacketPreferredSymetricAlgorithm    = 11,
    PGPSignatureSubpacketRevocationKey                 = 12,
    PGPSignatureSubpacketIssuer                        = 16,
    PGPSignatureSubpacketNotationData                  = 20,
    PGPSignatureSubpacketPreferredHashAlgorithm        = 21,
    PGPSignatureSubpacketPreferredCompressionAlgorithm = 22,
    PGPSignatureSubpacketKeyServerPreference           = 23,
    PGPSignatureSubpacketPreferredKeyServer            = 24,
    PGPSignatureSubpacketPrimaryUserID                 = 25,
    PGPSignatureSubpacketPolicyURI                     = 26,
    PGPSignatureSubpacketKeyFlags                      = 27,
    PGPSignatureSubpacketSignerUserID                  = 28,
    PGPSignatureSubpacketReasonForRevocation           = 29,
    PGPSignatureSubpacketFeatures                      = 30,
    PGPSignatureSubpacketSignatureTarget               = 31,
    PGPSignatureSubpacketEmbeddedSignature             = 32

};

#endif
