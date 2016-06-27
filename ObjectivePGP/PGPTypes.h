//
//  PGPTypes.h
//  PGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#pragma once

#ifndef NS_DESIGNATED_INITIALIZER
#define NS_DESIGNATED_INITIALIZER
#endif

static NSString * const PGPErrorDomain = @"ObjectivePGP";

typedef NS_ENUM(NSInteger, PGPErrorCode) {
    PGPErrorGeneral = -1,
    PGPErrorPassphraseRequired = 5,
    PGPErrorPassphraseInvalid = 6
};

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
    PGPInvalidPacketTag                                      = 0,
    PGPPublicKeyEncryptedSessionKeyPacketTag                 = 1,
    PGPSignaturePacketTag                                    = 2,
    PGPSymetricKeyEncryptedSessionKeyPacketTag               = 3,  //TODO
    PGPOnePassSignaturePacketTag                             = 4,
    PGPSecretKeyPacketTag                                    = 5,
    PGPPublicKeyPacketTag                                    = 6,
    PGPSecretSubkeyPacketTag                                 = 7,
    PGPCompressedDataPacketTag                               = 8,  
    PGPSymmetricallyEncryptedDataPacketTag                   = 9,  //TODO
    PGPMarkerPacketTag                                       = 10, //Ignored (Obsolete Literal Packet)
    PGPLiteralDataPacketTag                                  = 11,
    PGPTrustPacketTag                                        = 12,
    PGPUserIDPacketTag                                       = 13,
    PGPPublicSubkeyPacketTag                                 = 14,
    PGPUserAttributePacketTag                                = 17,
    PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag = 18,
    PGPModificationDetectionCodePacketTag                    = 19,
};

// 9.1.  Public-Key Algorithms
typedef NS_ENUM(UInt8, PGPPublicKeyAlgorithm) {
    PGPPublicKeyAlgorithmRSA                  = 1,
    PGPPublicKeyAlgorithmRSAEncryptOnly       = 2,
    PGPPublicKeyAlgorithmRSASignOnly          = 3,
    PGPPublicKeyAlgorithmElgamal              = 16,// Elgamal (Encrypt-Only)
    PGPPublicKeyAlgorithmDSA                  = 17,
    PGPPublicKeyAlgorithmElliptic             = 18,
    PGPPublicKeyAlgorithmECDSA                = 19,
    PGPPublicKeyAlgorithmElgamalEncryptorSign = 20,// Deprecated ?
    PGPPublicKeyAlgorithmDiffieHellman        = 21,
    PGPPublicKeyAlgorithmPrivate1             = 100,
    PGPPublicKeyAlgorithmPrivate2             = 101,
    PGPPublicKeyAlgorithmPrivate3             = 102,
    PGPPublicKeyAlgorithmPrivate4             = 103,
    PGPPublicKeyAlgorithmPrivate5             = 104,
    PGPPublicKeyAlgorithmPrivate6             = 105,
    PGPPublicKeyAlgorithmPrivate7             = 106,
    PGPPublicKeyAlgorithmPrivate8             = 107,
    PGPPublicKeyAlgorithmPrivate9             = 108,
    PGPPublicKeyAlgorithmPrivate10            = 109,
    PGPPublicKeyAlgorithmPrivate11            = 110
};

// 9.2.  Symmetric-Key Algorithms
typedef NS_ENUM(UInt8, PGPSymmetricAlgorithm) {
    PGPSymmetricPlaintext  = 0,
    PGPSymmetricIDEA       = 1, // 8 bytes (64-bit) block size, key length: 2 bytes (16 bit)
    PGPSymmetricTripleDES  = 2, // 8 bytes (64-bit) block size
    PGPSymmetricCAST5      = 3, // aka CAST-128 is a symmetric block cipher with a block-size of 8 bytes (64bit) and a variable key-size of up to 16 bytes (128 bits).
    PGPSymmetricBlowfish   = 4, // 8 bytes (64 bit) block size, key length: 16 bits (4-56 bits)
    PGPSymmetricAES128     = 7, // 16 bytes (128 bit), key length 128 bit
    PGPSymmetricAES192     = 8, // 16 bytes (128 bit), key length 192 bit
    PGPSymmetricAES256     = 9, // 16 bytes (128 bit), key length 256 bit
    PGPSymmetricTwofish256 = 10, // 16 bytes (128 bit)
    PGPSymmetricMax
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

typedef NS_ENUM(UInt8, PGPSignatureType) {
    PGPSignatureBinaryDocument                          = 0x00,
    PGPSignatureCanonicalTextDocument                   = 0x01,
    PGPSignatureStandalone                              = 0x02,
    PGPSignatureGenericCertificationUserIDandPublicKey  = 0x10, // Self-Signature
    PGPSignaturePersonalCertificationUserIDandPublicKey = 0x11, // Self-Signature
    PGPSignatureCasualCertificationUserIDandPublicKey   = 0x12, // Self-Signature
    PGPSignaturePositiveCertificationUserIDandPublicKey = 0x13, // Self-Signature
    PGPSignatureSubkeyBinding                           = 0x18, // Self-Signature
    PGPSignaturePrimaryKeyBinding                       = 0x19,
    PGPSignatureDirectlyOnKey                           = 0x1F, // 0x1F: Signature directly on a key (key) - Self-Signature
    PGPSignatureKeyRevocation                           = 0x20, // 0x20: Key revocation signature (key_revocation)
    PGPSignatureSubkeyRevocation                        = 0x28, // 0x28: Subkey revocation signature (subkey_revocation)
    PGPSignatureCertificationRevocation                 = 0x30, // 0x30: Certification revocation signature (cert_revocation)
    PGPSignatureTimestamp                               = 0x40,
    PGPSignature3PartyConfirmation                      = 0x50
};

typedef NS_ENUM(UInt8, PGPSignatureSubpacketType) {
    PGPSignatureSubpacketTypeSignatureCreationTime         = 2,
    PGPSignatureSubpacketTypeSignatureExpirationTime       = 3,
    PGPSignatureSubpacketTypeExportableCertification       = 4,
    PGPSignatureSubpacketTypeTrustSignature                = 5, //TODO
    PGPSignatureSubpacketTypeRegularExpression             = 6, //TODO
    PGPSignatureSubpacketTypeRevocable                     = 7, //TODO
    PGPSignatureSubpacketTypeKeyExpirationTime             = 9,
    PGPSignatureSubpacketTypePreferredSymetricAlgorithm    = 11,
    PGPSignatureSubpacketTypeRevocationKey                 = 12,//TODO
    PGPSignatureSubpacketTypeIssuerKeyID                   = 16,
    PGPSignatureSubpacketTypeNotationData                  = 20,//TODO
    PGPSignatureSubpacketTypePreferredHashAlgorithm        = 21,
    PGPSignatureSubpacketTypePreferredCompressionAlgorithm = 22,
    PGPSignatureSubpacketTypeKeyServerPreference           = 23,
    PGPSignatureSubpacketTypePreferredKeyServer            = 24,
    PGPSignatureSubpacketTypePrimaryUserID                 = 25,
    PGPSignatureSubpacketTypePolicyURI                     = 26,
    PGPSignatureSubpacketTypeKeyFlags                      = 27,
    PGPSignatureSubpacketTypeSignerUserID                  = 28,
    PGPSignatureSubpacketTypeReasonForRevocation           = 29,
    PGPSignatureSubpacketTypeFeatures                      = 30,
    PGPSignatureSubpacketTypeSignatureTarget               = 31,//TODO
    PGPSignatureSubpacketTypeEmbeddedSignature             = 32 //TODO
};

// 5.2.3.21.  Key Flags
typedef NS_ENUM(UInt8, PGPSignatureFlags) {
    PGPSignatureFlagAllowCertifyOtherKeys                      = 0x01,// indicates that this key may be used to certify other keys
    PGPSignatureFlagAllowSignData                              = 0x02,// indicates that this key may be used to sign data.
    PGPSignatureFlagAllowEncryptCommunications                 = 0x04,// indicates that this key may be used to encrypt communication.
    PGPSignatureFlagAllowEncryptStorage                        = 0x08,// indicates that this key may be used to encrypt storage.
    PGPSignatureFlagSecretComponentMayBeSplit                  = 0x10,// indicates that the secret components of this key may have been split using a secret-sharing mechanism.
    PGPSignatureFlagAllowAuthentication                        = 0x20,// indicates that this key may be used for authentication.
    PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons = 0x80 // indicates that the secret components of this key may be in the possession of more than one person.
};

// 5.2.3.17.  Key Server Preferences
typedef NS_ENUM(UInt8, PGPKeyServerPreferenceFlags) {
    PGPKeyServerPreferenceNoModify = 0x80 // No-modify
};

// 5.2.3.24.  Features
typedef NS_ENUM(UInt8, PGPFeature) {
    PGPFeatureModificationDetection = 0x01 // Modification Detection (packets 18 and 19)
};

// 3.7.1.  String-to-Key (S2K) Specifier Types
typedef NS_ENUM(UInt8, PGPS2KSpecifier) {
    PGPS2KSpecifierSimple            = 0,
    PGPS2KSpecifierSalted            = 1,
    PGPS2KSpecifierIteratedAndSalted = 3
};

typedef NS_ENUM(UInt8, PGPS2KUsage) {
    PGPS2KUsageNone               = 0,
    PGPS2KUsageEncryptedAndHashed = 254,
    PGPS2KUsageEncrypted          = 255
};
