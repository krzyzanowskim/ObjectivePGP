//
//  PGPSignatureSubpacketCreationTime.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
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

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing  _Nullable *)error {
    let timestamp = CFSwapInt32HostToBig((UInt32)[self.value timeIntervalSince1970]);
    let valueData = [NSData dataWithBytes:&timestamp length:PGPSignatureSubpacketLength];

    let type = self.class.type;
    let typedData = [NSMutableData dataWithBytes:&type length:1];
    [typedData appendData:valueData];


    let output = [NSMutableData data];
    [output appendData:[PGPPacket buildNewFormatLengthDataForData:typedData]];
    [output appendData:typedData];
    return output;
}

@end

NS_ASSUME_NONNULL_END
