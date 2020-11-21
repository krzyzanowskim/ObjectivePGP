//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPExportableProtocol.h"
#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(UInt8, PGPLiteralPacketFormat) {
    PGPLiteralPacketBinary = 'b',
    PGPLiteralPacketText = 't',
    PGPLiteralPacketTextUTF8 = 'u'
};

@interface PGPLiteralPacket : PGPPacket <PGPExportable, NSCopying>

@property (nonatomic) PGPLiteralPacketFormat format;
@property (nonatomic, copy) NSDate *timestamp;
@property (nonatomic, copy, nullable) NSString *filename;

@property (nonatomic, copy) NSData *literalRawData;

- (instancetype)initWithData:(NSData *)rawData;
+ (PGPLiteralPacket *)literalPacket:(PGPLiteralPacketFormat)format withData:(NSData *)rawData;

@end

NS_ASSUME_NONNULL_END
