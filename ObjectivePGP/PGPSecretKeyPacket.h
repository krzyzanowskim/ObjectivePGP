//
//  PGPSecretKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyPacket.h"
#import "PGPS2K.h"

@interface PGPSecretKeyPacket : PGPPublicKeyPacket

@property (assign, getter = isEncrypted) BOOL encrypted;
@property (assign) PGPS2KUsage s2kUsage;
@property (strong) PGPS2K *s2k;
@property (assign) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (strong, readonly) NSData *ivData;
@property (strong, readonly) NSArray *secretMPI;

/**
 *  Decrypt packet
 *
 *  @param passphrase Password
 *  @param error      error
 *
 *  @return YES on success
 */
- (BOOL) decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error;


@end
