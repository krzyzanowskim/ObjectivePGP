//
//  PGPCompressedPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 02/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPCompressedPacket : PGPPacket <NSCopying>

@property (nonatomic, readonly) PGPCompressionAlgorithm compressionType;
@property (nonatomic, copy, readonly) NSData *decompressedData;

- (instancetype)initWithData:(NSData *)dataToCompress type:(PGPCompressionAlgorithm)type;

@end
