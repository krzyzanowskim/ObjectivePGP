//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPCompressedPacket : PGPPacket <NSCopying>

@property (nonatomic, readonly) PGPCompressionAlgorithm compressionType;
@property (nonatomic, copy, readonly) NSData *decompressedData;

- (instancetype)initWithData:(NSData *)data type:(PGPCompressionAlgorithm)type;

@end

NS_ASSUME_NONNULL_END
