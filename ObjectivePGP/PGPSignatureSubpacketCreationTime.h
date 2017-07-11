//
//  PGPSignatureSubpacketCreationTime.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//
//  5.2.3.4.  Signature Creation Time
//  Signature Creation Time MUST be present in the hashed area.

#import "PGPTypes.h"
#import "PGPMacros.h"
#import "PGPExportableProtocol.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignatureSubpacketCreationTime : NSObject <PGPExportable>

@property (nonatomic, copy, readonly) NSDate *value;
@property (class, nonatomic, readonly) PGPSignatureSubpacketType type;

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithDate:(NSDate *)date NS_DESIGNATED_INITIALIZER;

+ (instancetype)packetWithData:(NSData *)packetBodyData;

@end

NS_ASSUME_NONNULL_END
