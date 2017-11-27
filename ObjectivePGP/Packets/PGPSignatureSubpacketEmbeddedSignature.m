//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPSignatureSubpacketEmbeddedSignature.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPMacros+Private.h"
#import "NSData+PGPUtils.h"
#import "PGPPacket+Private.h"
#import "PGPPacketHeader.h"
#import "PGPFoundation.h"

// PGPSignatureSubpacketTypeEmbeddedSignature

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignatureSubpacketEmbeddedSignature ()

@property (nonatomic, copy, readonly) PGPSignaturePacket *signaturePacket;

@end

@implementation PGPSignatureSubpacketEmbeddedSignature

- (instancetype)initWithSignature:(PGPSignaturePacket *)signature {
    if ((self = [super init])) {
        _signaturePacket = [signature copy];
    }
    return self;
}

+ (instancetype)packetWithData:(NSData *)packetBodyData {
    let signaturePacket = [PGPSignaturePacket packetWithBody:packetBodyData];
    let embeddedSignature = [[PGPSignatureSubpacketEmbeddedSignature alloc] initWithSignature:signaturePacket];
    return embeddedSignature;
}

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    let type = PGPSignatureSubpacketTypeEmbeddedSignature;
    let typedData = [NSMutableData dataWithBytes:&type length:1];

    let signatureValue = PGPCast(self.signaturePacket, PGPSignaturePacket);
    let _Nullable signatureBody = [signatureValue buildFullSignatureBodyData];
    if (!signatureBody) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Unable to export packet. Can't build signature." }];
        }
        return nil;
    }

    [typedData appendData:signatureBody];

    let output = [NSMutableData data];
    let length = [PGPPacketHeader buildNewFormatLengthDataForData:typedData];
    [output appendData:length];
    [output appendData:typedData];
    
    return output;
}

- (id)copyWithZone:(nullable NSZone *)zone {
    return [[PGPSignatureSubpacketEmbeddedSignature alloc] initWithSignature:[self.signaturePacket copyWithZone:zone]];
}

@end

NS_ASSUME_NONNULL_END
