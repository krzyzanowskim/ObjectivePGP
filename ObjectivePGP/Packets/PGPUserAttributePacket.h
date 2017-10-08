//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPUserAttributeSubpacket;

@interface PGPUserAttributePacket : PGPPacket <NSCopying>

// array of PGPUserAttributeSubpacket
@property (nonatomic) NSArray<PGPUserAttributeSubpacket *> *subpackets;

@end

NS_ASSUME_NONNULL_END
