//
//  PGPCompressedPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 02/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  TODO: add support for ZIP and BZIP2

#import "PGPCompressedPacket.h"
#import "NSData+Stream.h"
#import "NSData+zlib.h"

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
    switch (self.compressionType) {
        case PGPCompressionZLIB:
            self.decompressedData = [compressedData zlibDecompressed:error];
            break;

        default:
            @throw [NSException exceptionWithName:@"Unknown Compression" reason:@"Given compression algoritm is not supported" userInfo:nil];
            break;
    }

    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    NSMutableData *packetBody = [NSMutableData data];
    
    // - One octet that gives the algorithm used to compress the packet.
    [packetBody appendBytes:&_compressionType length:sizeof(_compressionType)];
    
    // - Compressed data, which makes up the remainder of the packet.
    switch (self.compressionType) {
        case PGPCompressionZLIB:
            [packetBody appendData:[self.decompressedData zlibCompressed:error]];
            break;
            
        default:
            @throw [NSException exceptionWithName:@"Unknown Compression" reason:@"Given compression algoritm is not supported" userInfo:nil];
            break;
    }
    [packetBody appendData:[self.decompressedData zlibCompressed:error]];
    
    return [packetBody copy];
}

@end

//ret = (int)inflateInit2(&z.zstream, -15)
