//
//  MKDataScannerDataProvider.h
//  MKDataScanner
//
//  Created by Marcin Krzyzanowski on 10/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MKDataProvider.h"

@interface MKDataScannerDataProvider : NSObject <MKDataProvider>
- (instancetype)initWithData:(NSData *)data;
@end
