//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPSignatureSubpacketCreationTime.h"
#import "NSData+PGPUtils.h"
#import "PGPPacket.h"
#import "PGPPacket+Private.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

static const NSUInteger PGPSignatureSubpacketLength = 4;

@implementation PGPSignatureSubpacketCreationTime

- (instancetype)initWithDate:(NSDate *)date {
    if ((self = [super init])) {
        _value = [date copy];
    }
    return self;
}

+ (PGPSignatureSubpacketType)type {
    return PGPSignatureSubpacketTypeSignatureCreationTime;
}

+ (instancetype)packetWithData:(NSData *)packetBodyData {
    UInt32 signatureCreationTimestamp = 0;
    [packetBodyData getBytes:&signatureCreationTimestamp length:PGPSignatureSubpacketLength];
    signatureCreationTimestamp = CFSwapInt32BigToHost(signatureCreationTimestamp);
    let date = [NSDate dateWithTimeIntervalSince1970:signatureCreationTimestamp];
    return [[PGPSignatureSubpacketCreationTime alloc] initWithDate:date];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(nullable NSZone *)zone {
    return [[PGPSignatureSubpacketCreationTime alloc] initWithDate:self.value];
}

@end

NS_ASSUME_NONNULL_END
