//
//  PGPModificationDetectionCodePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  MDC

#import "PGPModificationDetectionCodePacket.h"
#import "NSData+PGPUtils.h"

#import <CommonCrypto/CommonCrypto.h>

@implementation PGPModificationDetectionCodePacket

- (instancetype)initWithData:(NSData *)data
{
    if (self = [self init]) {
        self->_hashData = [data pgp_SHA1];
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPModificationDetectionCodePacketTag; // 19
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // 5.14.  Modification Detection Code Packet (Tag 19)
    NSAssert(self.bodyData.length == CC_SHA1_DIGEST_LENGTH, @"A Modification Detection Code packet MUST have a length of 20 octets");

    self->_hashData = [packetBody subdataWithRange:(NSRange){position,CC_SHA1_DIGEST_LENGTH}];
    position = position + self.hashData.length;

    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    NSData *bodyData = [self.hashData subdataWithRange:(NSRange) {0,CC_SHA1_DIGEST_LENGTH}]; // force limit to 20 octets

    NSMutableData *data = [NSMutableData data];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];
    
    return [data copy];
}

@end
