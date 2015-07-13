//
//  PGPPKCSEme.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPPKCSEme : NSObject

+ (NSData *) encodeMessage:(NSData *)m keyModulusLength:(NSUInteger)k error:(NSError * __autoreleasing *)error;
+ (NSData *) decodeMessage:(NSData *)m error:(NSError * __autoreleasing *)error;

@end
