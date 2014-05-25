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

@property (assign, readonly) PGPSignatureSubpacketType type;
@property (strong, readonly) id value;

- (instancetype) initWithBody:(NSData *)packetBody type:(PGPSignatureSubpacketType)type range:(NSRange)range;
+ (PGPSignatureSubpacket *) subpacketWithType:(PGPSignatureSubpacketType)type andValue:(id)value;

- (void) parseSubpacketBody:(NSData *)packetBody;
- (NSData *) exportSubpacket:(NSError *__autoreleasing *)error;

@end
