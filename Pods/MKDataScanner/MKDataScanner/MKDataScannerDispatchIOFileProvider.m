//
//  MKDataScannerFileProvider.m
//  MKDataScanner
//
//  Created by Marcin Krzyzanowski on 09/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "MKDataScannerDispatchIOFileProvider.h"

@interface MKDataScannerDispatchIOFileProvider ()
@property (copy) NSURL *fileURL;
@property (assign) NSInteger fileSize;
@property (strong) dispatch_io_t dispatchIO;
@property (strong) dispatch_queue_t queue;
@property (assign) NSInteger localOffset;
@end

@implementation MKDataScannerDispatchIOFileProvider

- (instancetype) initWithFileURL:(NSURL *)fileURL
{
    NSParameterAssert(fileURL.fileURL);
    if (self = [self init]) {
        _fileURL = fileURL;
        
        NSNumber* theSize = nil;
        [self.fileURL getResourceValue:&theSize forKey:NSURLFileSizeKey error:nil];
        _fileSize = [theSize integerValue];

        _queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        _dispatchIO = dispatch_io_create_with_path (DISPATCH_IO_RANDOM, [fileURL.path UTF8String], 0, O_RDONLY, _queue, nil);
    }
    return self;
}

- (void)dealloc
{
    dispatch_io_close(self.dispatchIO, 0);
}

#pragma mark - MKDataProvider

- (NSData *)dataForRange:(NSRange)range
{
    __block NSMutableData *totalData = [NSMutableData data];
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_io_read(self.dispatchIO, range.location, range.length, self.queue, ^(bool done, dispatch_data_t data, int error) {
        if (data) {
            [totalData appendData:(NSData *)data];
        }
        
        if (done) {
            dispatch_semaphore_signal(semaphore);
        }
    });
    
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return totalData.length > 0 ? [totalData copy] : nil;
}

- (NSInteger)offset
{
    return self.localOffset;
}

- (void)setOffset:(NSInteger)offset
{
    NSParameterAssert(offset >= 0);
    self.localOffset = offset;
}

- (BOOL)isAtEnd
{
    if (self.offset >= self.fileSize) {
        return YES;
    }
    return NO;
}

- (NSUInteger)size
{
    return self.fileSize;
}

@end
