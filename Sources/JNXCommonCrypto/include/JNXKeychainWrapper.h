//
//  JNXKeychainWrapper.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-12.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface JNXKeychainWrapper : NSObject

@property (nonatomic,retain)		NSString	*processName;
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
@property (nonatomic,retain)		NSString	*accessGroup;
#endif

+ (JNXKeychainWrapper *)sharedKeychainWrapper;

- (id)objectForKey:(NSString *)key;
- (BOOL)setObject:(id)object forKey:(NSString *)key;
- (BOOL)removeObjectForKey:(NSString *)key;

@end
