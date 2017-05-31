//
//  PGPLiteralPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

typedef NS_ENUM(UInt8, PGPLiteralPacketFormat) {
    PGPLiteralPacketBinary   = 'b',
    PGPLiteralPacketText     = 't',
    PGPLiteralPacketTextUTF8 = 'u'
};

@interface PGPLiteralPacket : PGPPacket

@property (nonatomic) PGPLiteralPacketFormat format;
@property (nonatomic) NSDate *timestamp;
@property (nonatomic) NSString *filename;

@property (nonatomic) NSData *literalRawData;

- (instancetype) initWithData:(NSData *)rawData;
+ (PGPLiteralPacket *) literalPacket:(PGPLiteralPacketFormat)format withData:(NSData *)rawData;

@end
