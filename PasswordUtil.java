package com.secureapp.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PASSWORD SECURITY UTILITY
 * - Uses SHA-256 with random salt
 * - Prevents rainbow table attacks via salting
 * - Constant-time comparison to prevent timing attacks
 */
public class PasswordUtil {

    private static final int SALT_LENGTH = 16;

    // Generate a cryptographically secure random salt
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Hash password with salt using SHA-256
    public static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(salt));
            byte[] hashedPassword = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found!", e);
        }
    }

    // Verify password using constant-time comparison (prevents timing attacks)
    public static boolean verifyPassword(String inputPassword, String storedHash, String salt) {
        String inputHash = hashPassword(inputPassword, salt);
        // MessageDigest.isEqual does constant-time comparison
        return MessageDigest.isEqual(
            Base64.getDecoder().decode(inputHash),
            Base64.getDecoder().decode(storedHash)
        );
    }
}
