package com.secureapp.security;

import java.util.HashMap;
import java.util.Map;

/**
 * RATE LIMITER - Brute Force Protection
 * Tracks failed login attempts per IP/username
 * Locks account after MAX_ATTEMPTS failures
 */
public class RateLimiter {

    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes

    private static final Map<String, Integer> attempts = new HashMap<>();
    private static final Map<String, Long> lockTime = new HashMap<>();

    public static boolean isBlocked(String identifier) {
        if (lockTime.containsKey(identifier)) {
            long lockedAt = lockTime.get(identifier);
            if (System.currentTimeMillis() - lockedAt < LOCK_DURATION_MS) {
                long remaining = (LOCK_DURATION_MS - (System.currentTimeMillis() - lockedAt)) / 1000;
                System.out.println("[RATE LIMITER] " + identifier + " is blocked. Try after " + remaining + "s");
                return true;
            } else {
                // Lock expired - reset
                attempts.remove(identifier);
                lockTime.remove(identifier);
            }
        }
        return false;
    }

    public static void recordFailedAttempt(String identifier) {
        int count = attempts.getOrDefault(identifier, 0) + 1;
        attempts.put(identifier, count);
        System.out.println("[RATE LIMITER] Failed attempt " + count + "/" + MAX_ATTEMPTS + " for: " + identifier);
        if (count >= MAX_ATTEMPTS) {
            lockTime.put(identifier, System.currentTimeMillis());
            System.out.println("[RATE LIMITER] ACCOUNT LOCKED for 15 minutes: " + identifier);
        }
    }

    public static void resetAttempts(String identifier) {
        attempts.remove(identifier);
        lockTime.remove(identifier);
    }

    public static int getRemainingAttempts(String identifier) {
        return MAX_ATTEMPTS - attempts.getOrDefault(identifier, 0);
    }
}
