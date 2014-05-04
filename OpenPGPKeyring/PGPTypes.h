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

#endif
