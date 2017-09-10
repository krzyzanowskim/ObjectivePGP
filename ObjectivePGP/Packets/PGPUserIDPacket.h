//
//  PGPUserID.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 13

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPPacket.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPUserIDPacket : PGPPacket

@property (nonatomic, copy, readonly) NSString *userID;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithUserID:(NSString *)userID NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
