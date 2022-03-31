//
//  NSData+PEM.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-13.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSData (PEM)

- (NSData *)dataFromPEMSection;
- (NSData *)dataByAddingPEMPrivateHeader;
- (NSData *)dataByAddingPEMPublicHeader;


@end
