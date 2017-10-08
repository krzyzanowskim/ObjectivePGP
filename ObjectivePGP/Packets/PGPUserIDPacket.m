//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPUserIDPacket.h"
#import "PGPPacket+Private.h"
#import "PGPFoundation.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPUserIDPacket ()

@property (nonatomic, copy, readwrite) NSString *userID;

@end

@implementation PGPUserIDPacket

- (instancetype)initWithUserID:(NSString *)userID {
    if ((self = [super init])) {
        _userID = [userID copy];
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPUserIDPacketTag;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@ %@", [super description], self.userID];
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    self.userID = [[NSString alloc] initWithData:packetBody encoding:NSUTF8StringEncoding];
    position = position + packetBody.length;

    return position;
}

- (nullable NSData *)export:(NSError *__autoreleasing *)error {
    return [PGPPacket buildPacketOfType:self.tag withBody:^NSData * {
        return [self.userID dataUsingEncoding:NSUTF8StringEncoding];
    }];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToUserIDPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToUserIDPacket:(PGPUserIDPacket *)packet {
    return PGPEqualObjects(self.userID, packet.userID);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.userID.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable duplicate = PGPCast([super copyWithZone:zone], PGPUserIDPacket);
    if (!duplicate) {
        return nil;
    }
    duplicate.userID = self.userID;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
