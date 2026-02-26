import { Router } from 'express';
import { signup, verifyEmail, signin, verifyLogin, resendOtp, getMe, signout } from '../controllers/authController.js';
import { requireAuth } from '../middleware/auth.js';
import { authRateLimiter, resendOtpRateLimiter } from '../middleware/rateLimit.js';

const router = Router();

router.use(authRateLimiter);

router.post('/signup', signup);
router.post('/verify-email', verifyEmail);
router.post('/signin', signin);
router.post('/verify-login', verifyLogin);
router.post('/resend-otp', resendOtpRateLimiter, resendOtp);
router.post('/signout', signout);

router.get('/me', requireAuth, getMe);

export default router;
