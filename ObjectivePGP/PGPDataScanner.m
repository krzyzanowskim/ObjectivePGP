//
//  PGPDataScanner.m
//  
//
//  Created by Scott Morrison on 2024-02-29.
//

#import "PGPDataScanner.h"
#import "PGPMacros+Private.h"

@interface PGPDataScanner( )
@property (readwrite,copy,atomic) NSData * data;
@end

@implementation PGPDataScanner
@synthesize data = _data;
@synthesize location = _location;

-(instancetype)init{
    NSAssert(NO,@"Must call initWithData:");
    self = [super init];
    return self;
}

-(instancetype)initWithData:(NSData*)data{
    self = [super init];
    if (self){
        _location = 0;
        _data = data;
    }
    return self;
}
-(BOOL)isAtEnd{
    return self.location>=self.data.length;
}

-(BOOL)scanData:(NSData*)data intoData:(NSData * _Nullable __autoreleasing* _Nullable)dataRef{
    if (dataRef) {
        *dataRef = nil;
    }
    if (data.length == 0){
        return NO;
    }
    let proposedRange = NSMakeRange(self.location,data.length);
    if (NSMaxRange(proposedRange) > self.data.length){
        return NO;
    }
    let compareData = [self.data subdataWithRange:proposedRange];
    if ([data isEqualToData:compareData]){
        self.location+=data.length;
        if (dataRef) *dataRef= compareData;
        return YES;
    }
    return NO;
}

-(BOOL)scanUpToData:(NSData*)data intoData:(NSData * _Nullable __autoreleasing* _Nullable)dataRef{
    let loc = self.location;
    let range = [self.data rangeOfData:data options:0 range:NSMakeRange(loc,self.data.length-loc)];
    if (range.location != NSNotFound){
        if (dataRef) * dataRef = [self.data subdataWithRange:NSMakeRange(loc, range.location-loc)];
        self.location = range.location;
        return self.location > loc;
    }
    return NO;
}

@end
