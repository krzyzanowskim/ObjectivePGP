//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

//  5.12.1.  The Image Attribute Subpacket

#import "PGPUserAttributeImageSubpacket.h"
#import "PGPLogging.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPUserAttributeImageSubpacket

@synthesize type = _type;

- (instancetype)init {
    if ((self = [super init])) {
        _type = PGPUserAttributeSubpacketImage;
    }
    return self;
}

- (nullable NSData *)image {
    NSUInteger position = 0;
    // The first two octets of the image header contain the length of the image header.
    // Note that unlike other multi-octet numerical values in this document,
    // due to a historical accident this value is encoded as a little-endian number.
    UInt16 imageHeaderLength = 0;
    [self.valueData getBytes:&imageHeaderLength range:(NSRange){position, 2}];
    imageHeaderLength = CFSwapInt16LittleToHost(imageHeaderLength);
    position = position + 2;

    // The image header length is followed by a single octet for the image header version.
    UInt8 version = 0;
    [self.valueData getBytes:&version range:(NSRange){position, 1}];
    position = position + 1;

    if (version != 1) {
        PGPLogWarning(@"Unknown image header version.");
        return nil;
    }

    // The only currently defined encoding format is the value 1 to indicate JPEG.
    UInt8 encodingFormat = 0;
    [self.valueData getBytes:&encodingFormat range:(NSRange){position, 1}];
    position = position + 1;

    if (encodingFormat != 1) {
        PGPLogWarning(@"Unknown image encodign format.");
        return nil;
    }

    // The rest of the version 1 image header is made up of 12 reserved octets, all of which MUST be set to 0.
    const UInt8 twelveBytes[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
    if (memcmp(twelveBytes, [self.valueData subdataWithRange:(NSRange){position, 12}].bytes, 12) != 0) {
        PGPLogWarning(@"Unexpected values.");
        return nil;
    }
    position = position + 12;

    // The rest of the image subpacket contains the image itself.
    return [self.valueData subdataWithRange:(NSRange){position, self.valueData.length - position}];
}

- (void)setImage:(nullable NSData *)image {
    let valueData = [NSMutableData data];

    let imageLength = CFSwapInt16HostToLittle((UInt16)image.length);
    [valueData appendBytes:&imageLength length:2];

    UInt8 headerVersion = 1;
    [valueData appendBytes:&headerVersion length:1];

    UInt8 encodingFormat = 1;
    [valueData appendBytes:&encodingFormat length:1];

    const UInt8 twelveBytes[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
    [valueData appendBytes:&twelveBytes length:12];

    [valueData appendData:image];

    self.valueData = valueData;
}

@end

NS_ASSUME_NONNULL_END
