//
//  PGPSignaturePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPublicKeyPacket.h"
#import "PGPSignatureSubpacket.h"
#import "PGPCommon.h"
#import "PGPKeyID.h"

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
@property (assign) UInt8 version;
@property (assign) PGPSignatureType signatureType;
@property (copy) NSDate *creationDate;
@property (assign) PGPPublicKeyAlgorithm publicKeyAlgorithm;
@property (assign) PGPHashAlgorithm hashAlgoritm;
@property (copy) NSSet *MPIs; // key algorithm specific MPIs

@property (assign) UInt16 hashValue;
@property (strong) PGPKeyID *issuerKeyID;

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
- (id) valueOfSubacketOfType:(PGPSignatureSubpacketType)type found:(BOOL *)isFound;

@end
