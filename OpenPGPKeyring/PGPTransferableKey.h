//
//  PGPTransferableKey.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

typedef NS_ENUM(NSUInteger, PGPTransferableType) {
    PGPTransferableUnknown = 0,
    PGPTransferableSecret  = 1,
    PGPTransferablePublic  = 2
};

@interface PGPTransferableKey : NSObject

@property (assign) PGPTransferableType type;
@property (strong, nonatomic) NSArray *revocationSignatures;

@end
