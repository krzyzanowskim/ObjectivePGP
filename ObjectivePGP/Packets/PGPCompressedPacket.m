//
//  PGPCompressedPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 02/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  TODO: add support for ZIP and BZIP2

#import "PGPCompressedPacket.h"
#import "NSData+compression.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPMacros+Private.h"

@implementation PGPCompressedPacket

- (instancetype)initWithData:(NSData *)dataToCompress type:(PGPCompressionAlgorithm)type {
    if (self = [self init]) {
        self->_decompressedData = dataToCompress;
        self->_compressionType = type;
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPCompressedDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // - One octet that gives the algorithm used to compress the packet.
    [packetBody getBytes:&_compressionType length:sizeof(_compressionType)];
    position = position + 1;

    // - Compressed data, which makes up the remainder of the packet.
    NSData *compressedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];

    // TODO: for ZIP use AgileBits/objective-zip
    switch (self.compressionType) {
        case PGPCompressionZLIB:
        case PGPCompressionZIP:
            self.decompressedData = [compressedData zlibDecompressed:error compressionType:self.compressionType];
            break;
        case PGPCompressionBZIP2:
            self.decompressedData = [compressedData bzip2Decompressed:error];
            break;

        default:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"This type of compression is not supported" }];
            }
            @throw [NSException exceptionWithName:@"Unsupported Compression" reason:@"Compression type is not supported" userInfo:nil];
            break;
    }

    compressedData = nil;
    return position;
}

- (NSData *)export:(NSError *__autoreleasing *)error {
    let bodyData = [NSMutableData data];

    // - One octet that gives the algorithm used to compress the packet.
    [bodyData appendBytes:&_compressionType length:sizeof(_compressionType)];

    // - Compressed data, which makes up the remainder of the packet.
    NSData * _Nullable compressedData = nil;
    switch (self.compressionType) {
        case PGPCompressionZLIB:
            compressedData = [self.decompressedData zlibCompressed:error];
            break;
        case PGPCompressionBZIP2:
            compressedData = [self.decompressedData bzip2Compressed:error];
            break;

        default:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"This type of compression is not supported" }];
            }
            return nil;
            break;
    }
    NSAssert(compressedData, @"Compression failed");
    [bodyData pgp_appendData:compressedData];

    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return bodyData;
    }];
}

@end

// ret = (int)inflateInit2(&z.zstream, -15)
