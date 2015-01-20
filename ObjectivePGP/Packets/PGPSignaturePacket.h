//
//  PGPSignaturePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPublicKeyPacket.h"
#import "PGPCommon.h"

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

@interface PGPSignaturePacket : NSObject
@property (assign) PGPSignatureType signatureType;
@property (strong) NSData *keyID; // 8 bytes long
@property (strong) NSDate *creationData;
@property (assign) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign) PGPHashAlgorithm hashAlgoritm;
@property (strong) NSSet *MPIs; // key algorithm specific MPIs

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
@end
