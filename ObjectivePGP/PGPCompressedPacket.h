//
//  PGPCompressedPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 02/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

// 9.3.  Compression Algorithms
typedef NS_ENUM(UInt8, PGPCompressionAlgorithm) {
    PGPCompressionUncompressed = 0,
    PGPCompressionZIP          = 1, //TODO: Unsupported
    PGPCompressionZLIB         = 2,
    PGPCompressionBZIP2        = 3
};

@interface PGPCompressedPacket : PGPPacket
@property (assign, readonly) PGPCompressionAlgorithm compressionType;
@property (strong) NSData *decompressedData;

- (instancetype)initWithData:(NSData *)dataToCompress type:(PGPCompressionAlgorithm)type;

@end
