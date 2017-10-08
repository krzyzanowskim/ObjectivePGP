//
//  PGPModificationDetectionCodePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPModificationDetectionCodePacket : PGPPacket <NSCopying>

@property (nonatomic, copy, readonly) NSData *hashData;

- (instancetype)initWithData:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
