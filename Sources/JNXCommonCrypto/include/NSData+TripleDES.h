//
//  NSData+_DES.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSString (TripleDES)
- (NSData *)tripleDESEncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
@end

@interface NSData (TripleDES)

- (NSData *)tripleDESEncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
- (NSData *)tripleDESDecryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
- (NSData *)tripleDESEnOrDecrypt:(BOOL)enordecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;

@end
