//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPCompressedPacket.h"
#import "NSData+compression.h"
#import "NSMutableData+PGPUtils.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"
#import "PGPLogging.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPCompressedPacket ()

@property (nonatomic, readwrite) PGPCompressionAlgorithm compressionType;
@property (nonatomic, copy, readwrite) NSData *decompressedData;

@end

@implementation PGPCompressedPacket

- (instancetype)initWithData:(NSData *)data type:(PGPCompressionAlgorithm)type {
    if (self = [self init]) {
        _decompressedData = [data copy];
        _compressionType = type;
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPCompressedDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // - One octet that gives the algorithm used to compress the packet.
    [packetBody getBytes:&_compressionType length:sizeof(_compressionType)];
    position = position + 1;

    // - Compressed data, which makes up the remainder of the packet.
    let compressedData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
    position = position + compressedData.length;

    switch (self.compressionType) {
        case PGPCompressionZIP:
            self.decompressedData = [compressedData zipDecompressed:error];
            break;
        case PGPCompressionZLIB:
            self.decompressedData = [compressedData zlibDecompressed:error];
            break;
        case PGPCompressionBZIP2:
            self.decompressedData = [compressedData bzip2Decompressed:error];
            break;

        default:
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"This type of compression is not supported" }];
            }
            break;
    }

    return position;
}

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    let bodyData = [NSMutableData data];

    // - One octet that gives the algorithm used to compress the packet.
    [bodyData appendBytes:&_compressionType length:sizeof(_compressionType)];

    // - Compressed data, which makes up the remainder of the packet.
    NSData * _Nullable compressedData = nil;
    switch (self.compressionType) {
        case PGPCompressionZIP:
            compressedData = [self.decompressedData zipCompressed:error];
            break;
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

    if (error && *error) {
        PGPLogDebug(@"Compression failed: %@", (*error).localizedDescription);
        return nil;
    }
    [bodyData pgp_appendData:compressedData];

    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return bodyData;
    }];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToCompressedPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToCompressedPacket:(PGPCompressedPacket *)packet {
    return  self.compressionType == packet.compressionType &&
            PGPEqualObjects(self.decompressedData, packet.decompressedData);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.compressionType;
    result = prime * result + self.decompressedData.hash;
    return result;
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    let duplicate = PGPCast([super copyWithZone:zone], PGPCompressedPacket);
    PGPAssertClass(duplicate, PGPCompressedPacket)
    duplicate.compressionType = self.compressionType;
    duplicate.decompressedData = self.decompressedData;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
