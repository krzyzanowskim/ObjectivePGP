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
        _version = 0x03;
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

    [packetBody getBytes:&_version range:(NSRange){position, 1}];
    position = position + 1;

    [packetBody getBytes:&_signatureType range:(NSRange){position, 1}];
    position = position + 1;

    [packetBody getBytes:&_hashAlgorith range:(NSRange){position, 1}];
    position = position + 1;

    [packetBody getBytes:&_publicKeyAlgorithm range:(NSRange){position, 1}];
    position = position + 1;

    PGPKeyID *keyID = [[PGPKeyID alloc] initWithLongKey:[packetBody subdataWithRange:(NSRange){position, 8}]];
    self.keyID = keyID;
    position = position + 8;

    [packetBody getBytes:&_notNested range:(NSRange){position, 1}];
    position = position + 1;

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

    [bodyData appendBytes:&_notNested length:1];

    NSMutableData *data = [NSMutableData data];
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];

    return [data copy];
}

@end
