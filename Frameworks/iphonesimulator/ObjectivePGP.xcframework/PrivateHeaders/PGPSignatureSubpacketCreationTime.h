//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//  5.2.3.4.  Signature Creation Time
//  Signature Creation Time MUST be present in the hashed area.

#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPExportableProtocol.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignatureSubpacketCreationTime : NSObject <NSCopying>

@property (nonatomic, copy, readonly) NSDate *value;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithDate:(NSDate *)date NS_DESIGNATED_INITIALIZER;

+ (instancetype)packetWithData:(NSData *)packetBodyData;

@end

NS_ASSUME_NONNULL_END
