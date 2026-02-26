import { rateLimit } from 'express-rate-limit';

const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

/** General auth routes: 50 requests per 15 minutes per IP. */
export const authRateLimiter = rateLimit({
  windowMs: WINDOW_MS,
  limit: 50,
  message: { error: 'Too many requests', message: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Resend OTP: 3 requests per 15 minutes per IP. */
export const resendOtpRateLimiter = rateLimit({
  windowMs: WINDOW_MS,
  limit: 3,
  message: { error: 'Too many requests', message: 'You can request a new code only 3 times per 15 minutes. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
