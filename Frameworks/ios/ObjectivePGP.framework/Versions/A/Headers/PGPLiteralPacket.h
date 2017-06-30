//
//  PGPLiteralPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPExportableProtocol.h"
#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(UInt8, PGPLiteralPacketFormat) { PGPLiteralPacketBinary = 'b', PGPLiteralPacketText = 't', PGPLiteralPacketTextUTF8 = 'u' };

@interface PGPLiteralPacket : PGPPacket <PGPExportable>

@property (nonatomic) PGPLiteralPacketFormat format;
@property (nonatomic) NSDate *timestamp;
@property (nonatomic, nullable) NSString *filename;

@property (nonatomic) NSData *literalRawData;

- (instancetype)initWithData:(NSData *)rawData;
+ (PGPLiteralPacket *)literalPacket:(PGPLiteralPacketFormat)format withData:(NSData *)rawData;

@end

NS_ASSUME_NONNULL_END
