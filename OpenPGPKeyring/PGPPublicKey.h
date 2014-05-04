//
//  OpenPGPPublicKey.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 6

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPPublicKey : NSObject

@property (assign, readonly, nonatomic) PGPPacketTag tag; // 6
@property (assign, readonly) UInt8 version;
@property (assign, readonly) UInt32 timestamp;
@property (assign, readonly) PGPPublicKeyAlgorithm algorithm;

- (void) parsePacketBody:(NSData *)packetBody;

@end
