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

@interface PGPCryptoCFB : NSObject

+ (NSData *) decryptData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData;

+ (NSData *) encryptData:(NSData *)encryptedData
          sessionKeyData:(NSData *)sessionKeyData // s2k produceSessionKeyWithPassphrase
      symmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
                      iv:(NSData *)ivData;

@end
