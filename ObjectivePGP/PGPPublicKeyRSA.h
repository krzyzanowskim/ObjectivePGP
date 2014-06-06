//
//  PGPPublicKeyAlgorithmRSA.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@class PGPSecretKeyPacket, PGPPublicKeyPacket;

@interface PGPPublicKeyRSA : NSObject

+ (NSData *) publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;

+ (NSData *) publicDecrypt:(NSData *)toDecrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;
+ (NSData *) privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket;

@end
