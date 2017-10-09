//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//  Tag 13

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPPacket.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPUserIDPacket : PGPPacket <NSCopying>

@property (nonatomic, copy, readonly) NSString *userID;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithUserID:(NSString *)userID NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
