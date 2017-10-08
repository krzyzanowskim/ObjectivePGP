//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//  Tag 12

#import "PGPPacketFactory.h"
#import <Foundation/Foundation.h>

@interface PGPTrustPacket : PGPPacket <NSCopying>

@property (nonatomic, copy, readonly) NSData *data;

@end
