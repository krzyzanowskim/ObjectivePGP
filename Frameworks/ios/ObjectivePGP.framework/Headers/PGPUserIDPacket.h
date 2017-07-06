//
//  PGPUserID.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 13

#import "PGPPacketFactory.h"
#import <Foundation/Foundation.h>

@interface PGPUserIDPacket : PGPPacket

@property (nonatomic, copy, readonly) NSString *userID;

@end
