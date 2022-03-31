//
//  NSString+hexString.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-27.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSString (hexString)

- (NSData *)hexstringData;

@end

@interface NSData (hexString)

- (NSString *)hexString;

@end
