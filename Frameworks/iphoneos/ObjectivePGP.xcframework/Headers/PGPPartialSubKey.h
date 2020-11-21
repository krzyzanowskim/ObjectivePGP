//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPPartialKey.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPPartialSubKey : PGPPartialKey <NSCopying>

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets __attribute__((unavailable("Not the designated initializer")));

- (instancetype)initWithPacket:(PGPPacket *)packet NS_DESIGNATED_INITIALIZER;

@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSArray<PGPPacket *> *)allPackets;

@end

NS_ASSUME_NONNULL_END
