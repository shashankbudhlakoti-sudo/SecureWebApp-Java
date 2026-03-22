package com.secureapp.controller;

import com.secureapp.model.User;
import com.secureapp.security.InputValidator;
import com.secureapp.security.JWTManager;
import com.secureapp.security.PasswordHasher;

import java.util.HashMap;
import java.util.Map;

/**
 * =============================================
 * Security Feature: Authentication Controller
 * =============================================
 * Handles: Register, Login, Logout
 * Simulates a REST API controller
 */
public class AuthController {

    // Simulated database (In production: use real DB with PreparedStatements)
    private static Map<String, User> userDatabase = new HashMap<>();
    private static Map<String, String> saltStorage = new HashMap<>(); // username -> salt
    private static int nextId = 1;

    // ============ REGISTER ============
    public static String register(String username, String password, String email) {
        System.out.println("\n[REGISTER] Attempting to register: " + username);

        // Step 1: Validate inputs
        InputValidator.ValidationResult usernameCheck = InputValidator.validate("username", username);
        if (!usernameCheck.isValid) return "ERROR: " + usernameCheck.message;

        InputValidator.ValidationResult emailCheck = InputValidator.validate("email", email);
        if (!emailCheck.isValid) return "ERROR: " + emailCheck.message;

        if (!InputValidator.isValidUsername(username))
            return "ERROR: Username must be 3-20 chars, only letters/numbers/underscore";

        if (!InputValidator.isValidEmail(email))
            return "ERROR: Invalid email format";

        if (!InputValidator.isValidPassword(password))
            return "ERROR: Password must be 8+ chars with uppercase, lowercase, digit, and special char";

        // Step 2: Check if user already exists
        if (userDatabase.containsKey(username))
            return "ERROR: Username already exists";

        // Step 3: Hash password with salt
        String hashedPassword = PasswordHasher.createHashedPassword(password);

        // Step 4: Save user
        User newUser = new User(nextId++, username, hashedPassword, email, "USER");
        userDatabase.put(username, newUser);

        System.out.println("[REGISTER SUCCESS] User created: " + username);
        System.out.println("[SECURITY] Password stored as hash (never plain text): " + hashedPassword.substring(0, 20) + "...");
        return "SUCCESS: User registered successfully!";
    }

    // ============ LOGIN ============
    public static String login(String username, String password) {
        System.out.println("\n[LOGIN] Attempting login for: " + username);

        // Step 1: Validate inputs (prevent SQL injection)
        InputValidator.ValidationResult check = InputValidator.validate("username", username);
        if (!check.isValid) return "ERROR: " + check.message;

        // Step 2: Find user
        User user = userDatabase.get(username);
        if (user == null) {
            System.out.println("[LOGIN FAILED] User not found: " + username);
            return "ERROR: Invalid credentials"; // Don't reveal which field is wrong
        }

        // Step 3: Verify password
        if (!PasswordHasher.checkPassword(password, user.getPasswordHash())) {
            System.out.println("[LOGIN FAILED] Wrong password for: " + username);
            return "ERROR: Invalid credentials";
        }

        // Step 4: Generate JWT Token
        String token = JWTManager.generateToken(username, user.getRole());
        System.out.println("[LOGIN SUCCESS] Token issued for: " + username);
        System.out.println("[TOKEN] " + token.substring(0, 30) + "...(truncated)");

        return "SUCCESS: " + token;
    }

    // ============ ACCESS PROTECTED RESOURCE ============
    public static String accessDashboard(String token) {
        System.out.println("\n[ACCESS] Attempting to access dashboard...");

        if (!JWTManager.validateToken(token)) {
            return "ERROR: Unauthorized - Invalid or expired token";
        }

        String username = JWTManager.extractUsername(token);
        String role = JWTManager.extractRole(token);

        System.out.println("[ACCESS GRANTED] Welcome " + username + " (Role: " + role + ")");
        return "SUCCESS: Welcome to dashboard, " + username + "! Role: " + role;
    }

    // ============ ADMIN ONLY RESOURCE ============
    public static String accessAdminPanel(String token) {
        System.out.println("\n[ACCESS] Attempting to access admin panel...");

        if (!JWTManager.validateToken(token)) {
            return "ERROR: Unauthorized - Please login first";
        }

        String role = JWTManager.extractRole(token);
        if (!"ADMIN".equals(role)) {
            System.out.println("[ACCESS DENIED] Non-admin tried to access admin panel!");
            return "ERROR: Forbidden - Admin access required";
        }

        return "SUCCESS: Welcome to Admin Panel!";
    }

    // ============ LOGOUT ============
    public static String logout(String token) {
        JWTManager.invalidateToken(token);
        return "SUCCESS: Logged out successfully";
    }

    // For testing: add admin user
    public static void addAdminUser() {
        String hashedPassword = PasswordHasher.createHashedPassword("Admin@1234");
        User admin = new User(nextId++, "admin", hashedPassword, "admin@secure.com", "ADMIN");
        userDatabase.put("admin", admin);
        System.out.println("[SETUP] Admin user created");
    }
}
