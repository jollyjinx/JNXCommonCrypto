//
//  NSData+Base64.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-23.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSData (Base64)

+ (NSData *)dataFromBase64String:(NSString *)aString;
- (NSString *)base64EncodedString;

@end
