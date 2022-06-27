//
//  SecurityService.h
//  UpgradeModule
//
//  Created by Kevin on 2022/6/27.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SecurityService : NSObject

/// AES encrypt
/// @param key key
/// @param oriString string to encrypt
+ (NSString *)aes256_encrypt:(NSString *)key originString:(NSString *)oriString;


/// AES decrypt
/// @param key key
/// @param enString encode string
+ (NSString *)aes256_decrypt:(NSString *)key enString:(NSString *)enString;



/// obfuscate
/// @param oriString true string
+ (NSString *)obfuscate:(NSString *)oriString;


@end

NS_ASSUME_NONNULL_END
