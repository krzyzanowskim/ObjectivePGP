//
//  PGPSymmetricallyEncryptedDataPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"

@class PGPSecretKeyPacket, PGPPublicKeyPacket;

@interface PGPSymmetricallyEncryptedIntegrityProtectedDataPacket : PGPSymmetricallyEncryptedDataPacket
@property (assign) NSUInteger version;

- (BOOL) encrypt:(NSData *)literalPacketData symmetricAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData error:(NSError * __autoreleasing *)error;
- (NSArray *) decryptWithSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket sessionKeyAlgorithm:(PGPSymmetricAlgorithm)sessionKeyAlgorithm sessionKeyData:(NSData *)sessionKeyData isIntegrityProtected:(BOOL *)isIntegrityProtected  error:(NSError * __autoreleasing *)error;

@end
