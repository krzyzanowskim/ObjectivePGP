//
//  PGPCryptoUtils.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPCryptoUtils : NSObject

+ (NSUInteger) blockSizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger) keySizeOfSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm;
+ (NSUInteger) hashSizeOfHashAlhorithm:(PGPHashAlgorithm)hashAlgorithm;

@end
