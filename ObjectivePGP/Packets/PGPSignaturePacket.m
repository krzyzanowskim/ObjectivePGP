//
//  PGPSignaturePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//    5.2.  Signature Packet (Tag 2)
//    A Signature packet describes a binding between some public key and
//    some data.  The most common signatures are a signature of a file or a
//    block of text, and a signature that is a certification of a User ID.

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

#import "PGPSignaturePacket.h"

@implementation PGPSignaturePacket

@end
