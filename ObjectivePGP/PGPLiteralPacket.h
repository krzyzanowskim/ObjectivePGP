//
//  PGPLiteralPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

typedef NS_ENUM(UInt8, PGPLiteralPacketFormat) {
    PGPLiteralPacketBinary   = 0x62,
    PGPLiteralPacketText     = 0x74,
    PGPLiteralPacketTextUTF8 = 0x75
};

@interface PGPLiteralPacket : PGPPacket
@property (assign) PGPLiteralPacketFormat format;
@property (strong) NSDate *timestamp;
@property (strong) NSString *filename;

@end
