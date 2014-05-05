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

// 9.1.  Public-Key Algorithms
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

// 9.2.  Symmetric-Key Algorithms
typedef NS_ENUM(UInt8, PGPSymmetricAlgorithm) {
    PGPSymmetricPlaintext  = 0,
    PGPSymmetricIDEA       = 1,
    PGPSymmetricTripleDES  = 2,
    PGPSymmetricCAST5      = 3,
    PGPSymmetricBlowfish   = 4,
    PGPSymmetricAES128     = 7,
    PGPSymmetricAES192     = 8,
    PGPSymmetricAES256     = 9,
    PGPSymmetricTwofish256 = 10
};

// 9.4.  Hash Algorithms
typedef NS_ENUM(UInt8, PGPHashAlgorithm) {
    PGPHashMD5       = 1, //MD5  - deprecated
    PGPHashSHA1      = 2, //SHA1 - required
    PGPHashRIPEMD160 = 3, //RIPEMD160
    PGPHashSHA256    = 8, //SHA256
    PGPHashSHA384    = 9, //SHA384
    PGPHashSHA512    = 10,//SHA512
    PGPHashSHA224    = 11 //SHA224
};

// 9.3.  Compression Algorithms
typedef NS_ENUM(UInt8, PGPCompressionAlgorithm) {
    PGPCompressionUncompressed = 0,
    PGPCompressionZIP          = 1,
    PGPCompressionZLIB         = 2,
    PGPCompressionBZIP2        = 3
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
    PGPSignatureSubpacketSignatureCreationTime         = 2,
    PGPSignatureSubpacketSignatureExpirationTime       = 3,
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

// 5.2.3.21.  Key Flags
typedef NS_ENUM(UInt64, PGPSignatureFlags) {
    PGPSignatureFlagAllowCertifyOtherKeys                      = 0x01,// indicates that this key may be used to certify other keys
    PGPSignatureFlagAllowSignData                              = 0x02,// indicates that this key may be used to sign data.
    PGPSignatureFlagAllowEncryptCommunications                 = 0x04,// indicates that this key may be used to encrypt communication.
    PGPSignatureFlagAllowEncryptStorage                        = 0x08,// indicates that this key may be used to encrypt storage.
    PGPSignatureFlagSecretComponentMayBeSplit                  = 0x10,// indicates that the secret components of this key may have been split using a secret-sharing mechanism.
    PGPSignatureFlagAllowAuthentication                        = 0x20,// indicates that this key may be used for authentication.
    PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons = 0x80 // indicates that the secret components of this key may be in the possession of more than one person.
};

// 5.2.3.17.  Key Server Preferences
typedef NS_ENUM(UInt64, PGPKeyServerPreferenceFlags) {
    PGPKeyServerPreferenceNoModify = 0x80 // No-modify
};

// 5.2.3.24.  Features
typedef NS_ENUM(UInt8, PGPFeature) {
    PGPFeatureModificationDetection = 0x01 // Modification Detection (packets 18 and 19)
};

#endif
