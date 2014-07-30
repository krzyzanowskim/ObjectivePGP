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

// encryption
+ (NSData *) publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;
+ (NSData *) privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket;


// signature
+ (NSData *) publicDecrypt:(NSData *)toDecrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;
+ (NSData *) privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket;

@end
