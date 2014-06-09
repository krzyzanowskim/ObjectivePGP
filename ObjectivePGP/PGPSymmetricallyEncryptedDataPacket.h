//
//  PGPSymmetricallyEncryptedDataPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@class PGPSecretKeyPacket, PGPPublicKeyPacket;

@interface PGPSymmetricallyEncryptedDataPacket : PGPPacket
@property (strong) NSData *encryptedData;

//- (NSData *) decrypt:(PGPSecretKeyPacket *)secretKeyPacket;
- (void) encrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm sessionKeyData:(NSData *)sessionKeyData;

@end
