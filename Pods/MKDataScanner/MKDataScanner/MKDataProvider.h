//
//  MKDataProvider.h
//  MKDataScanner
//
//  Created by Marcin Krzyzanowski on 10/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol MKDataProvider <NSObject>

- (NSInteger) offset;
- (void) setOffset:(NSInteger)offset;
- (NSData *) dataForRange:(NSRange)range;
- (BOOL) isAtEnd;
- (NSUInteger) size;
@end
