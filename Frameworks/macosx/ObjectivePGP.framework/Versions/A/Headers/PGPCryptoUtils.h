//
//  PGPCryptoUtils.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTypes.h"
#import <Foundation/Foundation.h>

@interface PGPCryptoUtils : NSObject

+ (NSUInteger)blockSizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger)keySizeOfSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger)hashSizeOfHashAlhorithm:(PGPHashAlgorithm)hashAlgorithm;

@end
