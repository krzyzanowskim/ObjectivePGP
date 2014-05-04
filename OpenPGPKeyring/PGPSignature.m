//
//  PGPSignature.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSignature.h"

@implementation PGPSignature

- (instancetype) initWithBody:(NSData *)packetData
{
    if (self = [self init]) {
        [self parsePacketBody:packetData];
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPSignaturePacketTag;
}

/**
 *  5.2.  Signature Packet (Tag 2)
 *
 *  @param packetBody Packet body
 */
- (void)parsePacketBody:(NSData *)packetBody
{
    //  TODO: Implementations SHOULD accept V3 signatures
}

@end
