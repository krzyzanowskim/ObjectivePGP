//
//  PGPOnePassSignaturePacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 29/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPOnePassSignaturePacket.h"
#import "PGPKeyID.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPOnePassSignaturePacket

- (id)init {
    if (self = [super init]) {
        _version = 0x03;
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPOnePassSignaturePacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
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

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error {
    NSAssert(self.keyID, @"Missing keyID");

    weakify(self);
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        strongify(self)
        let bodyData = [NSMutableData data];

        [bodyData appendBytes:&self->_version length:1];
        [bodyData appendBytes:&self->_signatureType length:1];
        [bodyData appendBytes:&self->_hashAlgorith length:1];
        [bodyData appendBytes:&self->_publicKeyAlgorithm length:1];
        [bodyData appendData:[self.keyID exportKeyData]];

        [bodyData appendBytes:&self->_notNested length:1];

        return bodyData;
    }];
}

@end

NS_ASSUME_NONNULL_END
