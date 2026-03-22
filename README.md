# Secure Web Application- Java

## Project 5: Building a Secure Web Application
**Internship Project | Codec Technologies**

---

## Features
- **Password Hashing** - SHA-256 with random salt (prevents rainbow table attacks)
- **JWT Authentication** - Stateless token-based auth (HMAC-SHA256 signed)
- **Role-Based Access Control (RBAC)** - ADMIN / USER roles
- **SQL Injection Prevention** - Regex-based input validation
- **XSS Prevention** - HTML sanitization of all inputs
- **Brute Force Protection** - Rate limiter (locks after 5 failed attempts)
- **Password Strength Validation** - Enforces uppercase, lowercase, digit & special char

---

## Project Structure
```
SecureWebApp/
  src/main/java/com/secureapp/
    model/          - User.java
    security/       - PasswordUtil.java, JWTUtil.java, InputValidator.java, RateLimiter.java
    controller/     - AuthController.java
    SecureWebApp.java (Main)
```

## How to Run
```bash
# Compile
javac -d out $(find src -name "*.java")

# Run
java -cp out com.secureapp.SecureWebApp
```

## Security Concepts Covered (OWASP Top 10)
| OWASP Risk | Protection Implemented |
|---|---|
| A01 - Broken Access Control | Role-Based Access (RBAC) + JWT |
| A02 - Cryptographic Failures | SHA-256 + Salt password hashing |
| A03 - Injection | SQL Injection + XSS detection |
| A07 - Authentication Failures | Rate limiting + Strong password policy |

## Technologies
- Java (No external libraries - pure JDK)
- SHA-256, HMAC-SHA256
- JWT (custom implementation)
