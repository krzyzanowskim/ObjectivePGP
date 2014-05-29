//
//  PGPOnePassSignaturePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 29/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPOnePassSignaturePacket.h"
#import "PGPKeyID.h"

@implementation PGPOnePassSignaturePacket

- (id)init
{
    if (self = [super init]) {
        self.version = 0x03;
    }
    return self;
}

- (PGPPacketTag)tag
{
    return PGPOnePassSignaturePacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];
    NSAssert(false, @"Not implemented");
    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    NSAssert(self.keyID, @"Missing keyID");

    NSMutableData *bodyData = [NSMutableData data];

    [bodyData appendBytes:&_version length:1];
    [bodyData appendBytes:&_signatureType length:1];
    [bodyData appendBytes:&_hashAlgorith length:1];
    [bodyData appendBytes:&_publicKeyAlgorithm length:1];
    [bodyData appendData:[self.keyID exportKeyData]];

    UInt8 flags = self.isNested ? 0x00 : 0x01;
    [bodyData appendBytes:&flags length:1];

    NSMutableData *data = [NSMutableData data];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];

    return [data copy];
}

@end
