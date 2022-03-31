//
//  NSData+AES128.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-23.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSString (AES128)
- (NSData *)AES128EncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
@end

@interface NSData (AES128)


+ (NSData *)randomAES128Cipher;
- (NSData *)AES128EncryptWithCipher:(NSData *)cipherData;
- (NSData *)AES128DecryptWithCipher:(NSData *)cipherData;
- (NSData *)AES128EnOrDecrypt:(BOOL)enordecrypt withCipher:(NSData *)cipherData;


- (NSData *)AES128EncryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
- (NSData *)AES128DecryptWithKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;
- (NSData *)AES128EnOrDecrypt:(BOOL)enordecrypt withKey:(NSData *)keyData initalizationVector:(NSData *)iVectorData;

@end
