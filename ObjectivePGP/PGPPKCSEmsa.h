//
//  PGPPKCS.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 22/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPPKCSEmsa : NSObject

+ (NSData *) encode:(PGPHashAlgorithm)hashAlgorithm message:(NSData *)m encodedMessageLength:(NSUInteger)emLen error:(NSError * __autoreleasing *)error;

@end
