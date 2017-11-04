//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPPacketFactory : NSObject

+ (nullable PGPPacket *)packetWithData:(NSData *)packetsData offset:(NSUInteger)offset nextPacketOffset:(nullable NSUInteger *)nextPacketOffset;

@end

NS_ASSUME_NONNULL_END
