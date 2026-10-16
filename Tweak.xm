// Tweak.xm - Network Recon
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// ==========================================
// HOOK NSURLSession - Bắt request/response
// ==========================================
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    
    NSString *url = request.URL.absoluteString;
    NSString *method = request.HTTPMethod;
    NSData *body = request.HTTPBody;
    
    // Log URL và method
    NSLog(@"[NET-RECON] ═══════════════════════════");
    NSLog(@"[NET-RECON] %@ %@", method, url);
    
    // Log headers (quan trọng - chứa device fingerprint)
    NSDictionary *headers = request.allHTTPHeaderFields;
    for (NSString *key in headers) {
        NSString *value = headers[key];
        // Chỉ log các header nghi vấn
        if ([key.lowercaseString containsString:@"device"] ||
            [key.lowercaseString containsString:@"x-"] ||
            [key.lowercaseString containsString:@"cookie"] ||
            [key.lowercaseString containsString:@"user-agent"] ||
            [key.lowercaseString containsString:@"sign"] ||
            [key.lowercaseString containsString:@"token"]) {
            NSLog(@"[NET-RECON] HEADER %@: %@", key, value);
        }
    }
    
    // Log body nếu là JSON
    if (body) {
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bodyStr) {
            // Chỉ log nếu body chứa từ khóa nghi vấn
            NSString *lower = bodyStr.lowercaseString;
            if ([lower containsString:@"jailbreak"] ||
                [lower containsString:@"root"]      ||
                [lower containsString:@"device"]    ||
                [lower containsString:@"security"]  ||
                [lower containsString:@"risk"]      ||
                [lower containsString:@"check"]     ||
                [lower containsString:@"sign"]      ||
                [lower containsString:@"token"]     ||
                [lower containsString:@"uuid"]      ||
                [lower containsString:@"idfa"]) {
                NSLog(@"[NET-RECON] BODY: %@", bodyStr);
            }
        }
    }
    
    // Gọi completion handler gốc nhưng bọc lại để log response
    void (^wrappedHandler)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        NSLog(@"[NET-RECON] RESPONSE %ld %@", (long)httpResp.statusCode, url);
        
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr) {
                NSString *lower = respStr.lowercaseString;
                if ([lower containsString:@"jailbreak"] ||
                    [lower containsString:@"jb"]          ||
                    [lower containsString:@"root"]        ||
                    [lower containsString:@"block"]       ||
                    [lower containsString:@"ban"]         ||
                    [lower containsString:@"risk"]        ||
                    [lower containsString:@"security"]    ||
                    [lower containsString:@"forbidden"]) {
                    NSLog(@"[NET-RECON] ⚠️ RESPONSE BODY: %@", respStr);
                }
            }
        }
        
        if (completionHandler) completionHandler(data, response, error);
    };
    
    return %orig(request, wrappedHandler);
}
%end

// ==========================================
// HOOK NSURLConnection (cho các app cũ)
// ==========================================
%hook NSURLConnection
+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {
    NSLog(@"[NET-RECON] SYNC %@ %@", request.HTTPMethod, request.URL.absoluteString);
    return %orig;
}
%end

// ==========================================
// HOOK CFNetwork - Bắt ở tầng thấp hơn
// ==========================================
extern void *CFReadStreamCreateForHTTPRequest(void *, void *);
%hookf(void *, CFReadStreamCreateForHTTPRequest, void *alloc, void *request) {
    NSLog(@"[NET-RECON] CFReadStream called");
    return %orig;
}

// ==========================================
// HOOK NSUserDefaults - Bắt xem app lưu gì
// ==========================================
%hook NSUserDefaults
- (void)setObject:(id)value forKey:(NSString *)defaultName {
    if (defaultName) {
        NSString *lower = defaultName.lowercaseString;
        if ([lower containsString:@"jailbreak"] ||
            [lower containsString:@"device"]    ||
            [lower containsString:@"uuid"]      ||
            [lower containsString:@"idfa"]      ||
            [lower containsString:@"token"]     ||
            [lower containsString:@"fingerprint"]) {
            NSLog(@"[NET-RECON] NSUserDefaults set %@ = %@", defaultName, value);
        }
    }
    %orig;
}
%end

// ==========================================
// HOOK KEYCHAIN - Bắt xem app lưu gì vào keychain
// ==========================================
extern OSStatus SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result);
%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    NSDictionary *dict = (__bridge NSDictionary *)attributes;
    NSLog(@"[NET-RECON] SecItemAdd: %@", dict);
    return %orig;
}
