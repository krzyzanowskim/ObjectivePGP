//
//  PGPCommon.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#pragma mark once

static NSString * PGPErrorDomain = @"ObjectivePGP";
static const UInt32 PGPIndeterminateLength = UINT32_MAX;


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

