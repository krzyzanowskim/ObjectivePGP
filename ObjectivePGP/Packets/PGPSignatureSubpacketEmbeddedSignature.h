//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//  5.2.3.26.  Embedded Signature

#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPExportableProtocol.h>
#import <ObjectivePGP/PGPSignatureSubpacket.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSignaturePacket;

@interface PGPSignatureSubpacketEmbeddedSignature : NSObject <NSCopying, PGPExportable>

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithSignature:(PGPSignaturePacket *)signature NS_DESIGNATED_INITIALIZER;

+ (instancetype)packetWithData:(NSData *)packetBodyData;

@end

NS_ASSUME_NONNULL_END
