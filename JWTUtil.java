package com.secureapp.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT (JSON Web Token) UTILITY
 * Implements JWT from scratch for learning:
 * Header.Payload.Signature
 * - No external libraries needed!
 * - Signed with HMAC-SHA256
 */
public class JWTUtil {

    private static final String SECRET_KEY = "MyS3cur3S3cr3tK3y!@#JavaSecureApp2024";
    private static final long EXPIRY_MS = 3600_000; // 1 hour

    // Create a JWT token
    public static String generateToken(String username, String role) {
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());

        long expiry = System.currentTimeMillis() + EXPIRY_MS;
        String payloadJson = String.format(
            "{\"sub\":\"%s\",\"role\":\"%s\",\"exp\":%d,\"iat\":%d}",
            username, role, expiry, System.currentTimeMillis()
        );
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());

        String signature = sign(header + "." + payload);
        return header + "." + payload + "." + signature;
    }

    // Validate and parse a JWT token
    public static Map<String, String> validateToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;

            String expectedSig = sign(parts[0] + "." + parts[1]);
            if (!constantTimeEquals(expectedSig, parts[2])) {
                System.out.println("[SECURITY] Invalid token signature!");
                return null;
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            Map<String, String> claims = parseJson(payloadJson);

            long exp = Long.parseLong(claims.get("exp"));
            if (System.currentTimeMillis() > exp) {
                System.out.println("[SECURITY] Token expired!");
                return null;
            }

            return claims;
        } catch (Exception e) {
            System.out.println("[SECURITY] Token validation failed: " + e.getMessage());
            return null;
        }
    }

    private static String sign(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256");
            mac.init(keySpec);
            return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(data.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }

    // Simple JSON key-value parser
    private static Map<String, String> parseJson(String json) {
        Map<String, String> map = new HashMap<>();
        json = json.replaceAll("[{}\"]", "");
        for (String pair : json.split(",")) {
            String[] kv = pair.split(":");
            if (kv.length == 2) map.put(kv[0].trim(), kv[1].trim());
        }
        return map;
    }

    // Constant-time string comparison to prevent timing attacks
    private static boolean constantTimeEquals(String a, String b) {
        byte[] aBytes = a.getBytes();
        byte[] bBytes = b.getBytes();
        if (aBytes.length != bBytes.length) return false;
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) result |= aBytes[i] ^ bBytes[i];
        return result == 0;
    }
}
