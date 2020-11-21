//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

@interface PGPPKCSEme : NSObject

+ (NSData *)encodeMessage:(NSData *)m keyModulusLength:(NSUInteger)k error:(NSError * __autoreleasing *)error;
+ (NSData *)decodeMessage:(NSData *)m error:(NSError * __autoreleasing *)error;

@end
