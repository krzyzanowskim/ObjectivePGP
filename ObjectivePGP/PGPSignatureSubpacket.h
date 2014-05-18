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

@property (assign) NSRange bodyRange;

@property (assign, readonly) PGPSignatureSubpacketType type;
@property (strong, readonly) id value;

- (instancetype) initWithBody:(NSData *)packetBody type:(PGPSignatureSubpacketType)type;
- (void) parseSubpacketBody:(NSData *)packetBody;
- (NSData *) exportSubpacket:(NSError *__autoreleasing *)error;

@end
