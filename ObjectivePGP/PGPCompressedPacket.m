//
//  PGPCompressedPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 02/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCompressedPacket.h"
#import "NSData+Stream.h"
#import "NSData+IDZGunzip.h"
#import <zlib.h>

@implementation PGPCompressedPacket

- (PGPPacketTag)tag
{
    return PGPCompressedDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // - One octet that gives the algorithm used to compress the packet.
    [packetBody getBytes:&_compressionType length:sizeof(_compressionType)];
    position = position + 1;

    // - Compressed data, which makes up the remainder of the packet.
    NSData *compressedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];

    //TODO: for ZIP use AgileBits/objective-zip
    NSError *decompressError = nil;
    switch (self.compressionType) {
        case PGPCompressionZLIB:
            self.decompressedData = [self decompressZlib:compressedData error:&decompressError];
            break;

        default:
            @throw [NSException exceptionWithName:@"Unknown Compression" reason:@"Given compression algoritm is not supported" userInfo:nil];
            break;
    }

    return position;
}

//ret = (int)inflateInit2(&z.zstream, -15);
- (NSData *) decompressZlib:(NSData *)compressedData error:(NSError * __autoreleasing *)error
{
    //return [compressedData gunzip:error];
    // 1950 is not gzip
    return nil;
}

@end
