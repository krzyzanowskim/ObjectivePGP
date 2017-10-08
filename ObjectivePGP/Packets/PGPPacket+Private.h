//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPacket.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPPacket ()

@property (nonatomic) BOOL indeterminateLength; // should not be used, but gpg uses it
@property (nonatomic, readwrite) PGPPacketTag tag;

+ (NSData *)buildNewFormatLengthDataForData:(NSData *)bodyData;

@end

NS_ASSUME_NONNULL_END
