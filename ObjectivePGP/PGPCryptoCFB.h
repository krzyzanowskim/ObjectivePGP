//
//  PGPCryptoCFB.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPS2K.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPCryptoCFB : NSObject

+ (nullable NSData *)decryptData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData;

+ (nullable NSData *)encryptData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData;

@end

NS_ASSUME_NONNULL_END
