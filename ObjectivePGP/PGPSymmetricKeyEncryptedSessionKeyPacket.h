//
//  PGPSymmetricKeyEncryptedSessionKeyPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPSymmetricKeyEncryptedSessionKeyPacket : PGPPacket

@property (assign) UInt8 version;
@property (assign) PGPSymmetricAlgorithm symmetricAlgorithm;
@property (assign) PGPS2KSpecifier specifier;

@end
