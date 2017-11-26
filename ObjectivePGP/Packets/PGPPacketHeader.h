//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>
#import <ObjectivePGP/PGPTypes.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPPacketHeader : NSObject

@property (nonatomic) UInt32 headerLength;
@property (nonatomic) UInt32 bodyLength;
@property (nonatomic) PGPPacketTag packetTag;

// New format only
@property (nonatomic, getter=isPartialLength) BOOL partialLength;

// Old format only
@property (nonatomic, getter=isIndeterminateLength) BOOL indeterminateLength;

+ (nullable PGPPacketHeader *)newFormatHeaderFromData:(NSData *)data;
+ (nullable PGPPacketHeader *)oldFormatHeaderFromData:(NSData *)data;

+ (void)getLengthFromNewFormatOctets:(NSData *)lengthOctetsData bodyLength:(UInt32 *)bodyLength bytesCount:(UInt8 *)bytesCount isPartial:(BOOL *)isPartial;

@end

NS_ASSUME_NONNULL_END
