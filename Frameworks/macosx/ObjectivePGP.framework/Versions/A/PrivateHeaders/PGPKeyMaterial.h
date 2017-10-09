//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>
#import "PGPMPI.h"

@interface PGPKeyMaterial: NSObject

@property (nonatomic) PGPMPI *n;
@property (nonatomic) PGPMPI *e;
@property (nonatomic) PGPMPI *d;
@property (nonatomic) PGPMPI *p;
@property (nonatomic) PGPMPI *q;
@property (nonatomic) PGPMPI *r;
@property (nonatomic) PGPMPI *g;
@property (nonatomic) PGPMPI *u;
@property (nonatomic) PGPMPI *x;
@property (nonatomic) PGPMPI *y;

@end
