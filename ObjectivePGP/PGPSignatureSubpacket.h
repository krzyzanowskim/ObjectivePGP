//
//  PGPSignatureSubPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPSignatureSubpacket : NSObject

@property (assign, readonly) NSRange bodyRange; // subrange range within parent packet

@property (assign) PGPSignatureSubpacketType type;
@property (strong) id value;

- (instancetype) initWithBody:(NSData *)packetBody type:(PGPSignatureSubpacketType)type range:(NSRange)range;
- (void) parseSubpacketBody:(NSData *)packetBody;
- (NSData *) exportSubpacket:(NSError *__autoreleasing *)error;

@end
