package com.secureapp.security;

import java.util.regex.Pattern;

/**
 * =============================================
 * Security Feature: Input Validation
 * =============================================
 * 
 * Prevents:
 * - SQL Injection (e.g., ' OR 1=1 --)
 * - XSS Attacks (<script>alert('hack')</script>)
 * - Command Injection (;rm -rf /)
 */
public class InputValidator {

    // SQL Injection patterns
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|--|;|'|\"|\\/\\*|\\*\\/|xp_|sp_)",
        Pattern.CASE_INSENSITIVE
    );

    // XSS patterns
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)(<script|</script|javascript:|on\\w+=|<iframe|<object|<embed|alert\\(|document\\.cookie)",
        Pattern.CASE_INSENSITIVE
    );

    // Valid username pattern: only alphanumeric + underscore
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,20}$");

    // Valid email pattern
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );

    public static boolean isSQLInjection(String input) {
        if (input == null) return false;
        return SQL_INJECTION_PATTERN.matcher(input).find();
    }

    public static boolean isXSSAttack(String input) {
        if (input == null) return false;
        return XSS_PATTERN.matcher(input).find();
    }

    public static boolean isValidUsername(String username) {
        if (username == null) return false;
        return USERNAME_PATTERN.matcher(username).matches();
    }

    public static boolean isValidEmail(String email) {
        if (email == null) return false;
        return EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isValidPassword(String password) {
        if (password == null || password.length() < 8) return false;
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(c -> "!@#$%^&*()_+-=[]{}|;':\",./<>?".indexOf(c) >= 0);
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    // Sanitize input - remove dangerous characters
    public static String sanitize(String input) {
        if (input == null) return null;
        return input
            .replace("'", "''")        // Escape SQL quotes
            .replace("<", "&lt;")       // Escape HTML tags
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace(";", "")           // Remove semicolons
            .trim();
    }

    // Comprehensive check
    public static ValidationResult validate(String field, String value) {
        if (value == null || value.isEmpty()) {
            return new ValidationResult(false, field + " cannot be empty");
        }
        if (isSQLInjection(value)) {
            System.out.println("[SECURITY ALERT] SQL Injection attempt detected in field: " + field + " | Value: " + value);
            return new ValidationResult(false, "Invalid characters detected in " + field);
        }
        if (isXSSAttack(value)) {
            System.out.println("[SECURITY ALERT] XSS Attack attempt detected in field: " + field);
            return new ValidationResult(false, "Invalid characters detected in " + field);
        }
        return new ValidationResult(true, "Valid");
    }

    public static class ValidationResult {
        public final boolean isValid;
        public final String message;

        public ValidationResult(boolean isValid, String message) {
            this.isValid = isValid;
            this.message = message;
        }
    }
}
