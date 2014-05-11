//
//  PGPS2K.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPString2Key : NSObject

@property (assign) PGPS2KSpecifier specifier;
@property (assign) PGPHashAlgorithm algorithm;
@property (retain) NSData *salt; // 8 bytes
@property (assign) UInt32 count;

@property (assign) NSUInteger length;

+ (PGPString2Key *) string2KeyFromData:(NSData *)data atPosition:(NSUInteger)position;
- (NSUInteger) parseS2K:(NSData *)data atPosition:(NSUInteger)position;
@end
