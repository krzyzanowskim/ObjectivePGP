//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPTypes.h"
#import <Foundation/Foundation.h>

@interface PGPPKCSEmsa : NSObject

+ (NSData *)encode:(PGPHashAlgorithm)hashAlgorithm message:(NSData *)m encodedMessageLength:(NSUInteger)emLen error:(NSError *__autoreleasing *)error;

@end
