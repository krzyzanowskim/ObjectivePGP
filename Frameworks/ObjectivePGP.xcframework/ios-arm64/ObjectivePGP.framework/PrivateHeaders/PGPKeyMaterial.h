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

@property (nonatomic, copy) PGPMPI *n;
@property (nonatomic, copy) PGPMPI *e;
@property (nonatomic, copy) PGPMPI *d;
@property (nonatomic, copy) PGPMPI *p;
@property (nonatomic, copy) PGPMPI *q;
@property (nonatomic, copy) PGPMPI *r;
@property (nonatomic, copy) PGPMPI *g;
@property (nonatomic, copy) PGPMPI *u;
@property (nonatomic, copy) PGPMPI *x;
@property (nonatomic, copy) PGPMPI *y;

@end
