package com.secureapp;

import com.secureapp.controller.AuthController;
import com.secureapp.security.InputValidator;

/**
 * ================================================================
 * PROJECT 1: BUILDING A SECURE WEB APPLICATION IN JAVA
 * ================================================================
 * 
 * OWASP Top 10 Security Features Implemented:
 * 1. ✅ Password Hashing with Salt (SHA-256)
 * 2. ✅ JWT Authentication (Stateless)
 * 3. ✅ SQL Injection Prevention (Input Validation)
 * 4. ✅ XSS Prevention (Input Sanitization)
 * 5. ✅ Role-Based Authorization (ADMIN/USER)
 * 6. ✅ Secure Password Policy (8+ chars, mixed)
 * 7. ✅ Token Expiry (1 hour)
 * 8. ✅ No sensitive data in error messages
 * 
 * Tools/Tech: Java, SHA-256, JWT, Input Validation
 * ================================================================
 */
public class SecureWebApp {

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("   SECURE WEB APPLICATION - JAVA PROJECT");
        System.out.println("=================================================\n");

        // Setup admin
        AuthController.addAdminUser();

        // ========== TEST 1: REGISTER ==========
        System.out.println("\n===== TEST 1: USER REGISTRATION =====");
        System.out.println(AuthController.register("rahul_123", "Rahul@2024", "rahul@email.com"));
        System.out.println(AuthController.register("amit_dev", "Amit#Pass1", "amit@email.com"));

        // Test weak password
        System.out.println("\n--- Weak Password Test ---");
        System.out.println(AuthController.register("weakuser", "12345", "weak@email.com"));

        // Test SQL injection in username
        System.out.println("\n--- SQL Injection Test ---");
        System.out.println(AuthController.register("'; DROP TABLE users; --", "Pass@1234", "hack@email.com"));

        // ========== TEST 2: LOGIN ==========
        System.out.println("\n===== TEST 2: LOGIN =====");
        String result = AuthController.login("rahul_123", "Rahul@2024");
        System.out.println("Login result: " + result.substring(0, Math.min(50, result.length())) + "...");

        // Extract token for next tests
        String token = null;
        if (result.startsWith("SUCCESS: ")) {
            token = result.substring(9);
        }

        // Test wrong password
        System.out.println("\n--- Wrong Password Test ---");
        System.out.println(AuthController.login("rahul_123", "wrongpassword"));

        // ========== TEST 3: ACCESS PROTECTED ROUTES ==========
        System.out.println("\n===== TEST 3: ACCESSING PROTECTED ROUTES =====");
        if (token != null) {
            System.out.println(AuthController.accessDashboard(token));
            System.out.println(AuthController.accessAdminPanel(token)); // Should fail - not admin
        }

        // ========== TEST 4: ADMIN ACCESS ==========
        System.out.println("\n===== TEST 4: ADMIN ACCESS =====");
        String adminResult = AuthController.login("admin", "Admin@1234");
        if (adminResult.startsWith("SUCCESS: ")) {
            String adminToken = adminResult.substring(9);
            System.out.println(AuthController.accessAdminPanel(adminToken)); // Should succeed
        }

        // ========== TEST 5: XSS PREVENTION ==========
        System.out.println("\n===== TEST 5: XSS ATTACK PREVENTION =====");
        String xssAttempt = "<script>alert('Hacked!')</script>";
        InputValidator.ValidationResult xssResult = InputValidator.validate("comment", xssAttempt);
        System.out.println("XSS Input: " + xssAttempt);
        System.out.println("Validation: " + xssResult.message);

        // ========== TEST 6: LOGOUT ==========
        System.out.println("\n===== TEST 6: LOGOUT =====");
        if (token != null) {
            System.out.println(AuthController.logout(token));
            // Try to access after logout
            System.out.println("Access after logout: " + AuthController.accessDashboard(token));
        }

        System.out.println("\n=================================================");
        System.out.println("   ALL SECURITY TESTS COMPLETED!");
        System.out.println("=================================================");
    }
}
