//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPPublicSubKeyPacket.h"

@implementation PGPPublicSubKeyPacket

- (PGPPacketTag)tag {
    return PGPPublicSubkeyPacketTag;
}

@end
