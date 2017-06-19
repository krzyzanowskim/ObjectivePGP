//
//  PGPPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPPacketFactory : NSObject

+ (nullable PGPPacket *) packetWithData:(NSData *)packetsData offset:(NSUInteger)offset nextPacketOffset:(nullable NSUInteger *)nextPacketOffset;

@end

NS_ASSUME_NONNULL_END
