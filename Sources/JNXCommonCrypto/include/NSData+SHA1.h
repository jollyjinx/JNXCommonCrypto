//
//  NSData+ZlibAddition.h
//  JNXLicense Framework
//
//  Created by Patrick Stein on 09.05.07.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSString (SHA1)
- (NSString *)sha1StringNoKey;
- (NSString *)sha1StringWithKey:(NSData *)keyData;
- (NSString *)sha1StringCompatible;
@end

@interface NSData (SHA1)
- (NSString *)sha1StringNoKey;
- (NSString *)sha1StringWithKey:(NSData *)keyData;
- (NSData *)sha1DataNoKey;
- (NSData *)sha1DataWithKey:(NSData *)keyData;
- (NSData *)sha1DataCompatible;
- (NSString *)sha1StringCompatible;
@end
