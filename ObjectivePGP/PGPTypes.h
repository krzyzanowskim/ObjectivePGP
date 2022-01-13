//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

#ifndef NS_DESIGNATED_INITIALIZER
#define NS_DESIGNATED_INITIALIZER
#endif

#ifdef NS_NOESCAPE
#undef NS_NOESCAPE
#endif

#ifndef NS_NOESCAPE
#define NS_NOESCAPE __attribute__((noescape))
#endif


static const UInt32 PGPUnknownLength = UINT32_MAX;
static NSString *const PGPErrorDomain = @"com.objectivepgp";

typedef NS_ERROR_ENUM(PGPErrorDomain, PGPErrorCode) {
    PGPErrorGeneral = -1,
    PGPErrorPassphraseRequired = 5,
    PGPErrorPassphraseInvalid = 6,
    /// Invalid signature. Signature is invalid or cannot be verified (eg. missing key)
    PGPErrorInvalidSignature = 7,
    /// The message is not signed.
    PGPErrorNotSigned = 8,
    /// Invalid PGP message. Invalid or corrupted data that can't be processed.
    PGPErrorInvalidMessage = 9,
    PGPErrorMissingSignature = 10,
    PGPErrorNotFound = 11,
    // for check signature with rootCA
    PGPErrorMissingPublicKeySignature = 12,
    PGPErrorMissingRootPublicKey = 13,
    PGPErrorInvalidRootPublicKey = 14

};

typedef NS_CLOSED_ENUM(NSInteger, PGPFormatType) {
    PGPFormatUnknown = 0,
    PGPFormatOld = 1,
    PGPFormatNew = 2
};

typedef NS_CLOSED_ENUM(NSUInteger, PGPHeaderPacketTag) {
    PGPHeaderPacketTagNewFormat = 0x40,
    PGPHeaderPacketTagAllwaysSet = 0x80
};

typedef NS_CLOSED_ENUM(UInt8, PGPPacketTag) {
    PGPInvalidPacketTag = 0,
    PGPPublicKeyEncryptedSessionKeyPacketTag = 1,
    PGPSignaturePacketTag = 2,
    PGPSymetricKeyEncryptedSessionKeyPacketTag = 3,
    PGPOnePassSignaturePacketTag = 4,
    PGPSecretKeyPacketTag = 5,
    PGPPublicKeyPacketTag = 6,
    PGPSecretSubkeyPacketTag = 7,
    PGPCompressedDataPacketTag = 8,
    PGPSymmetricallyEncryptedDataPacketTag = 9,
    PGPMarkerPacketTag = 10, // (Obsolete Literal Packet)
    PGPLiteralDataPacketTag = 11,
    PGPTrustPacketTag = 12,
    PGPUserIDPacketTag = 13,
    PGPPublicSubkeyPacketTag = 14,
    PGPUserAttributePacketTag = 17,
    PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag = 18,
    PGPModificationDetectionCodePacketTag = 19,
    PGPExperimentalPacketTag1 = 60,
    PGPExperimentalPacketTag2 = 61,
    PGPExperimentalPacketTag3 = 62,
    PGPExperimentalPacketTag4 = 63
};

typedef NS_CLOSED_ENUM(UInt8, PGPUserAttributeSubpacketType) {
    PGPUserAttributeSubpacketUnknown = 0x00,
    PGPUserAttributeSubpacketImage = 0x01 // The only currently defined subpacket type is 1, signifying an image.
};

// 9.1.  Public-Key Algorithms
typedef NS_CLOSED_ENUM(UInt8, PGPPublicKeyAlgorithm) {
    PGPPublicKeyAlgorithmRSA = 1,
    PGPPublicKeyAlgorithmRSAEncryptOnly = 2,
    PGPPublicKeyAlgorithmRSASignOnly = 3,
    PGPPublicKeyAlgorithmElgamal = 16, // Elgamal (Encrypt-Only)
    PGPPublicKeyAlgorithmDSA = 17,
    PGPPublicKeyAlgorithmECDH = 18, // encrypt-only
    PGPPublicKeyAlgorithmECDSA = 19, // sign-only
    PGPPublicKeyAlgorithmElgamalEncryptorSign = 20, // Deprecated ?
    PGPPublicKeyAlgorithmDiffieHellman = 21, // TODO: Deprecated?
    PGPPublicKeyAlgorithmEdDSA = 22, // sign-only
    PGPPublicKeyAlgorithmPrivate1 = 100,
    PGPPublicKeyAlgorithmPrivate2 = 101,
    PGPPublicKeyAlgorithmPrivate3 = 102,
    PGPPublicKeyAlgorithmPrivate4 = 103,
    PGPPublicKeyAlgorithmPrivate5 = 104,
    PGPPublicKeyAlgorithmPrivate6 = 105,
    PGPPublicKeyAlgorithmPrivate7 = 106,
    PGPPublicKeyAlgorithmPrivate8 = 107,
    PGPPublicKeyAlgorithmPrivate9 = 108,
    PGPPublicKeyAlgorithmPrivate10 = 109,
    PGPPublicKeyAlgorithmPrivate11 = 110
};

// 9.2.  Symmetric-Key Algorithms
typedef NS_CLOSED_ENUM(UInt8, PGPSymmetricAlgorithm) {
    PGPSymmetricPlaintext = 0,
    PGPSymmetricIDEA = 1, // 8 bytes (64-bit) block size, key length: 2 bytes (16 bit)
    PGPSymmetricTripleDES = 2, // 8 bytes (64-bit) block size
    PGPSymmetricCAST5 = 3, // aka CAST-128 is a symmetric block cipher with a block-size of 8 bytes (64bit) and a variable key-size of up to 16 bytes (128 bits).
    PGPSymmetricBlowfish = 4, // 8 bytes (64 bit) block size, key length: 16 bits (4-56 bits)
    PGPSymmetricAES128 = 7, // 16 bytes (128 bit), key length 128 bit
    PGPSymmetricAES192 = 8, // 16 bytes (128 bit), key length 192 bit
    PGPSymmetricAES256 = 9, // 16 bytes (128 bit), key length 256 bit
    PGPSymmetricTwofish256 = 10, // 16 bytes (128 bit)
    PGPSymmetricMax
};

// rfc4880bis 9.2.  ECC Curve OID
typedef NS_CLOSED_ENUM(UInt8, PGPCurve) {
    PGPCurveP256 = 0,
    PGPCurveP384 = 1,
    PGPCurveP521 = 2,
    PGPCurveBrainpoolP256r1 = 3,
    PGPCurveBrainpoolP512r1 = 4,
    PGPCurveEd25519 = 5,
    PGPCurve25519 = 6
};

// 9.4.  Hash Algorithms
typedef NS_CLOSED_ENUM(UInt8, PGPHashAlgorithm) {
    PGPHashUnknown = 0,
    PGPHashMD5 = 1, // MD5  - deprecated
    PGPHashSHA1 = 2, // SHA1 - required
    PGPHashRIPEMD160 = 3, // RIPEMD160
    PGPHashSHA256 = 8, // SHA256
    PGPHashSHA384 = 9, // SHA384
    PGPHashSHA512 = 10, // SHA512
    PGPHashSHA224 = 11, // SHA224
    PGPHashSHA3_256 = 12, // SHA3-256
    PGPHashSHA3_512 = 14 // SHA3-512
};

typedef NS_CLOSED_ENUM(UInt8, PGPSignatureType) {
    PGPSignatureBinaryDocument = 0x00,
    PGPSignatureCanonicalTextDocument = 0x01,
    PGPSignatureStandalone = 0x02,
    PGPSignatureGenericCertificationUserIDandPublicKey = 0x10, // Self-Signature
    PGPSignaturePersonalCertificationUserIDandPublicKey = 0x11, // Self-Signature
    PGPSignatureCasualCertificationUserIDandPublicKey = 0x12, // Self-Signature
    PGPSignaturePositiveCertificationUserIDandPublicKey = 0x13, // Self-Signature
    PGPSignatureSubkeyBinding = 0x18, // Self-Signature
    PGPSignaturePrimaryKeyBinding = 0x19,
    PGPSignatureDirectlyOnKey = 0x1F, // 0x1F: Signature directly on a key (key) - Self-Signature
    PGPSignatureKeyRevocation = 0x20, // 0x20: Key revocation signature (key_revocation)
    PGPSignatureSubkeyRevocation = 0x28, // 0x28: Subkey revocation signature (subkey_revocation)
    PGPSignatureCertificationRevocation = 0x30, // 0x30: Certification revocation signature (cert_revocation)
    PGPSignatureTimestamp = 0x40,
    PGPSignature3PartyConfirmation = 0x50,
    PGPSignatureUnknown = 0xFF
};

typedef NS_CLOSED_ENUM(UInt8, PGPSignatureSubpacketType) {
    PGPSignatureSubpacketTypeUnknown = 0, // Unknown
    PGPSignatureSubpacketTypeSignatureCreationTime = 2,
    PGPSignatureSubpacketTypeSignatureExpirationTime = 3,
    PGPSignatureSubpacketTypeExportableCertification = 4,
    PGPSignatureSubpacketTypeTrustSignature = 5, // TODO
    PGPSignatureSubpacketTypeRegularExpression = 6, // TODO
    PGPSignatureSubpacketTypeRevocable = 7, // TODO
    PGPSignatureSubpacketTypeKeyExpirationTime = 9,
    PGPSignatureSubpacketTypePreferredSymetricAlgorithm = 11,
    PGPSignatureSubpacketTypeRevocationKey = 12, // TODO
    PGPSignatureSubpacketTypeIssuerKeyID = 16,
    PGPSignatureSubpacketTypeNotationData = 20, // TODO
    PGPSignatureSubpacketTypePreferredHashAlgorithm = 21,
    PGPSignatureSubpacketTypePreferredCompressionAlgorithm = 22,
    PGPSignatureSubpacketTypeKeyServerPreference = 23,
    PGPSignatureSubpacketTypePreferredKeyServer = 24,
    PGPSignatureSubpacketTypePrimaryUserID = 25,
    PGPSignatureSubpacketTypePolicyURI = 26,
    PGPSignatureSubpacketTypeKeyFlags = 27,
    PGPSignatureSubpacketTypeSignerUserID = 28,
    PGPSignatureSubpacketTypeReasonForRevocation = 29,
    PGPSignatureSubpacketTypeFeatures = 30,
    PGPSignatureSubpacketTypeSignatureTarget = 31, // Seems unused at all, https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.26
    PGPSignatureSubpacketTypeEmbeddedSignature = 32,
    PGPSignatureSubpacketTypeIssuerFingerprint = 33, // TODO: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.28
    PGPSignatureSubpacketTypeIntendedRecipientFingerprint = 35, //TODO: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.29
    PGPSignatureSubpacketTypeAttestedCertifications = 37, // TODO: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.30
    PGPSignatureSubpacketTypeKeyBlock = 38 // TODO: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.31
};

// 5.2.3.21.  Key Flags
typedef NS_CLOSED_ENUM(UInt8, PGPSignatureFlags) {
    PGPSignatureFlagUnknown = 0x00,
    PGPSignatureFlagAllowCertifyOtherKeys = 0x01, // indicates that this key may be used to certify other keys
    PGPSignatureFlagAllowSignData = 0x02, // indicates that this key may be used to sign data.
    PGPSignatureFlagAllowEncryptCommunications = 0x04, // indicates that this key may be used to encrypt communication.
    PGPSignatureFlagAllowEncryptStorage = 0x08, // indicates that this key may be used to encrypt storage.
    PGPSignatureFlagSecretComponentMayBeSplit = 0x10, // indicates that the secret components of this key may have been split using a secret-sharing mechanism.
    PGPSignatureFlagAllowAuthentication = 0x20, // indicates that this key may be used for authentication.
    PGPSignatureFlagPrivateKeyMayBeInThePossesionOfManyPersons = 0x80 // indicates that the secret components of this key may be in the possession of more than one person.
};

// 5.2.3.17.  Key Server Preferences
typedef NS_CLOSED_ENUM(UInt8, PGPKeyServerPreferenceFlags) {
    PGPKeyServerPreferenceUnknown  = 0x00,
    PGPKeyServerPreferenceNoModify = 0x80 // No-modify
};

// 5.2.3.24.  Features
typedef NS_CLOSED_ENUM(UInt8, PGPFeature) {
    PGPFeatureModificationUnknown   = 0x00,
    PGPFeatureModificationDetection = 0x01 // Modification Detection (packets 18 and 19)
};

// 3.7.1.  String-to-Key (S2K) Specifier Types
typedef NS_CLOSED_ENUM(UInt8, PGPS2KSpecifier) {
    PGPS2KSpecifierSimple = 0,
    PGPS2KSpecifierSalted = 1,
    PGPS2KSpecifierIteratedAndSalted = 3,
    // GNU extensions to the S2K algorithm.
    // see: https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/DETAILS;h=8ead6a8f5250656f72aea99042f392cb6749b8ff;hb=refs/heads/master#l1309
    // The "gnu-dummy S2K" is the marker which will tell that this file does *not* actually contain the secret key.
    PGPS2KSpecifierGnuDummy = 101,
    // TODO: gnu-divert-to-card S2K
    PGPS2KSpecifierDivertToCard = 102
};

typedef NS_CLOSED_ENUM(UInt8, PGPS2KUsage) {
    PGPS2KUsageNonEncrypted = 0, // no passphrase
    PGPS2KUsageEncryptedAndHashed = 254,
    PGPS2KUsageEncrypted = 255
};

// 9.3.  Compression Algorithms
typedef NS_CLOSED_ENUM(UInt8, PGPCompressionAlgorithm) {
    PGPCompressionUncompressed = 0,
    PGPCompressionZIP = 1,
    PGPCompressionZLIB = 2,
    PGPCompressionBZIP2 = 3
};
