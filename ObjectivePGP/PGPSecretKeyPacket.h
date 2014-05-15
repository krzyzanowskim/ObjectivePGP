//
//  PGPSecretKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket.h"
#import "PGPString2Key.h"

@interface PGPSecretKeyPacket : PGPPublicKeyPacket

@property (assign) BOOL isEncrypted;
@property (assign) PGPS2KUsage s2kUsage;
@property (strong) PGPString2Key *s2k;
@property (assign) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (strong, readonly) NSData *ivData;
@property (strong, readonly) NSArray *secretMPI;

- (BOOL) decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error;


@end
