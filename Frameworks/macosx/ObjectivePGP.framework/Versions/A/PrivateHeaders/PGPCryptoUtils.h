//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPTypes.h"
#import "PGPSecretKeyPacket.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPCryptoUtils : NSObject

+ (NSUInteger)blockSizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger)keySizeOfSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger)hashSizeOfHashAlhorithm:(PGPHashAlgorithm)hashAlgorithm;
+ (NSData *)randomData:(NSUInteger)length;
+ (nullable NSData *)decrypt:(NSData *)data usingSecretKeyPacket:(PGPSecretKeyPacket *)keyPacket;

@end

NS_ASSUME_NONNULL_END
