//
//  PGPCryptoUtils.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSecretKeyPacket;

@interface PGPCryptoUtils : NSObject

+ (NSUInteger)blockSizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger)keySizeOfSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger)hashSizeOfHashAlhorithm:(PGPHashAlgorithm)hashAlgorithm;
+ (NSData *)randomData:(NSInteger)length;
+ (nullable NSData *)decryptData:(NSData *)data usingSecretKeyPacket:(PGPSecretKeyPacket *)keyPacket;

@end

NS_ASSUME_NONNULL_END
