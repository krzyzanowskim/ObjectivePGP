//
//  PGPDataScanner.h
//  
//
//  Created by Scott Morrison on 2024-02-29.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPDataScanner : NSObject
@property (assign,atomic) NSUInteger location;
@property (readonly,nullable) NSData*  data;
@property (readonly) BOOL isAtEnd;

-(instancetype)initWithData:(NSData*)data;
-(BOOL)scanData:(NSData*)data
       intoData:(NSData* _Nullable * _Nullable)dataRef;

-(BOOL)scanUpToData:(NSData*)data
           intoData:(NSData* _Nullable * _Nullable)dataRef;

-(BOOL)scanArmoredDataIntoBinaryData:(NSData* _Nullable __autoreleasing* _Nullable)binaryDataRef
                error:(NSError*_Nullable __autoreleasing* _Nullable)error;
@end

NS_ASSUME_NONNULL_END
