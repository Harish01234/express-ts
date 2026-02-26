import type { Request, Response } from 'express';
import { z } from 'zod';
import argon2 from 'argon2';
import { prisma } from '../lib/prisma.js';
import { signToken, verifyToken } from '../lib/jwt.js';
import { sendOtp, generateOtp } from '../lib/sendmail.js';
import { OtpType } from '../generated/prisma/enums.js';

const CREDENTIAL_PROVIDER = 'credential';
const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
const MAX_OTP_ATTEMPTS = 5;
const AUTH_COOKIE_NAME = 'auth_token';
const isProduction = process.env.NODE_ENV === 'production';

const signupSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255).trim(),
  email: z.string().email('Invalid email').max(255).toLowerCase().trim(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128)
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
      'Password must contain at least one lowercase letter, one uppercase letter, and one digit'
    ),
});

const signinSchema = z.object({
  email: z.string().email('Invalid email').max(255).toLowerCase().trim(),
  password: z.string().min(1, 'Password is required'),
});

const verifyEmailSchema = z.object({
  email: z.string().email('Invalid email').max(255).toLowerCase().trim(),
  otp: z.string().length(6, 'OTP must be 6 digits').regex(/^\d+$/, 'OTP must be digits only'),
});

const verifyLoginSchema = z.object({
  email: z.string().email('Invalid email').max(255).toLowerCase().trim(),
  otp: z.string().length(6, 'OTP must be 6 digits').regex(/^\d+$/, 'OTP must be digits only'),
});

const resendOtpSchema = z.object({
  email: z.string().email('Invalid email').max(255).toLowerCase().trim(),
  type: z.enum(['REGISTER', 'LOGIN']),
});

type SignupBody = z.infer<typeof signupSchema>;
type SigninBody = z.infer<typeof signinSchema>;
type VerifyEmailBody = z.infer<typeof verifyEmailSchema>;
type VerifyLoginBody = z.infer<typeof verifyLoginSchema>;
type ResendOtpBody = z.infer<typeof resendOtpSchema>;

function toSafeUser(user: { id: string; name: string; email: string; emailVerified: boolean; image: string | null; role: string }) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: user.emailVerified,
    image: user.image,
    role: user.role,
  };
}

function getBearerToken(req: Request): string | undefined {
  const fromCookie = req.cookies?.[AUTH_COOKIE_NAME];
  if (typeof fromCookie === 'string' && fromCookie.trim()) return fromCookie.trim();
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) return auth.slice(7).trim();
  const body = req.body as { token?: string };
  return typeof body?.token === 'string' ? body.token.trim() : undefined;
}

function setAuthCookie(res: Response, token: string, expiresAt: Date): void {
  const maxAgeMs = Math.max(0, expiresAt.getTime() - Date.now());
  res.cookie(AUTH_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: maxAgeMs,
    path: '/',
  });
}

function clearAuthCookie(res: Response): void {
  res.clearCookie(AUTH_COOKIE_NAME, {
    path: '/',
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
  });
}

function validationError(res: Response, parsed: { success: false; error: z.ZodError }): void {
  const msg = parsed.error.flatten().fieldErrors;
  const message = Object.entries(msg)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
    .join('; ');
  res.status(400).json({ error: 'Validation failed', message });
}

export async function signup(req: Request, res: Response): Promise<void> {
  try {
    const parsed = signupSchema.safeParse(req.body);
    if (!parsed.success) {
      validationError(res, parsed);
      return;
    }

    const { name, email, password } = parsed.data as SignupBody;

    const existing = await prisma.user.findFirst({
      where: { email, deletedAt: null },
      select: { id: true },
    });
    if (existing) {
      res.status(409).json({ error: 'Email already registered', message: 'An account with this email already exists.' });
      return;
    }

    const hashedPassword = await argon2.hash(password, { type: argon2.argon2id });
    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

    const user = await prisma.$transaction(async (tx) => {
      const u = await tx.user.create({
        data: {
          name,
          email,
          emailVerified: false,
          role: 'USER',
        },
      });
      await tx.account.create({
        data: {
          accountId: u.id,
          providerId: CREDENTIAL_PROVIDER,
          userId: u.id,
          password: hashedPassword,
        },
      });
      await tx.verification.create({
        data: {
          identifier: email,
          value: otp,
          type: OtpType.REGISTER,
          expiresAt,
          userId: u.id,
        },
      });
      return u;
    });

    await sendOtp({ to: email, type: 'REGISTER', otp });

    res.status(201).json({
      message: 'Account created. Check your email for the verification code.',
      user: toSafeUser(user),
    });
  } catch (err) {
    if (err && typeof err === 'object' && 'code' in err && err.code === 'P2002') {
      res.status(409).json({ error: 'Email already registered', message: 'An account with this email already exists.' });
      return;
    }
    console.error('[auth] signup error:', err);
    res.status(500).json({ error: 'Registration failed', message: 'Something went wrong. Please try again.' });
  }
}

export async function verifyEmail(req: Request, res: Response): Promise<void> {
  try {
    const parsed = verifyEmailSchema.safeParse(req.body);
    if (!parsed.success) {
      validationError(res, parsed);
      return;
    }

    const { email, otp } = parsed.data as VerifyEmailBody;

    const verification = await prisma.verification.findFirst({
      where: {
        identifier: email,
        type: OtpType.REGISTER,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
      select: { id: true, value: true, attemptCount: true, userId: true },
    });

    if (!verification) {
      res.status(400).json({ error: 'Invalid or expired code', message: 'Verification code is invalid or has expired. Request a new one.' });
      return;
    }

    if (verification.attemptCount >= MAX_OTP_ATTEMPTS) {
      res.status(400).json({ error: 'Too many attempts', message: 'Too many failed attempts. Request a new code.' });
      return;
    }

    if (verification.value !== otp) {
      await prisma.verification.update({
        where: { id: verification.id },
        data: { attemptCount: { increment: 1 } },
      });
      res.status(400).json({ error: 'Invalid code', message: 'Verification code is incorrect.' });
      return;
    }

    await prisma.$transaction([
      prisma.verification.update({
        where: { id: verification.id },
        data: { isUsed: true },
      }),
      prisma.user.update({
        where: { id: verification.userId! },
        data: { emailVerified: true },
      }),
    ]);

    const user = await prisma.user.findUniqueOrThrow({
      where: { id: verification.userId! },
      select: { id: true, name: true, email: true, emailVerified: true, image: true, role: true },
    });

    const { token, jti, expiresAt } = signToken({ sub: user.id, email: user.email, role: user.role });
    const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.socket?.remoteAddress ?? null;
    const userAgent = req.headers['user-agent'] ?? null;

    await prisma.session.create({
      data: {
        token: jti,
        expiresAt,
        userId: user.id,
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
      },
    });

    setAuthCookie(res, token, expiresAt);
    res.status(200).json({
      message: 'Email verified. You are signed in.',
      user: toSafeUser(user),
    });
  } catch (err) {
    console.error('[auth] verifyEmail error:', err);
    res.status(500).json({ error: 'Verification failed', message: 'Something went wrong. Please try again.' });
  }
}

export async function signin(req: Request, res: Response): Promise<void> {
  try {
    const parsed = signinSchema.safeParse(req.body);
    if (!parsed.success) {
      validationError(res, parsed);
      return;
    }

    const { email, password } = parsed.data as SigninBody;

    const user = await prisma.user.findFirst({
      where: { email, deletedAt: null },
      select: { id: true, name: true, email: true, emailVerified: true, image: true, role: true },
    });
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials', message: 'Email or password is incorrect.' });
      return;
    }

    const account = await prisma.account.findUnique({
      where: {
        providerId_accountId: { providerId: CREDENTIAL_PROVIDER, accountId: user.id },
      },
      select: { password: true },
    });
    if (!account?.password) {
      res.status(401).json({ error: 'Invalid credentials', message: 'Email or password is incorrect.' });
      return;
    }

    const valid = await argon2.verify(account.password, password);
    if (!valid) {
      res.status(401).json({ error: 'Invalid credentials', message: 'Email or password is incorrect.' });
      return;
    }

    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

    await prisma.verification.create({
      data: {
        identifier: email,
        value: otp,
        type: OtpType.LOGIN,
        expiresAt,
        userId: user.id,
      },
    });

    await sendOtp({ to: email, type: 'LOGIN', otp });

    res.status(200).json({
      message: 'Check your email for the login code.',
      email: user.email,
    });
  } catch (err) {
    console.error('[auth] signin error:', err);
    res.status(500).json({ error: 'Sign in failed', message: 'Something went wrong. Please try again.' });
  }
}

export async function verifyLogin(req: Request, res: Response): Promise<void> {
  try {
    const parsed = verifyLoginSchema.safeParse(req.body);
    if (!parsed.success) {
      validationError(res, parsed);
      return;
    }

    const { email, otp } = parsed.data as VerifyLoginBody;

    const verification = await prisma.verification.findFirst({
      where: {
        identifier: email,
        type: OtpType.LOGIN,
        isUsed: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
      select: { id: true, value: true, attemptCount: true, userId: true },
    });

    if (!verification) {
      res.status(400).json({ error: 'Invalid or expired code', message: 'Login code is invalid or has expired. Sign in again to get a new code.' });
      return;
    }

    if (verification.attemptCount >= MAX_OTP_ATTEMPTS) {
      res.status(400).json({ error: 'Too many attempts', message: 'Too many failed attempts. Sign in again to get a new code.' });
      return;
    }

    if (verification.value !== otp) {
      await prisma.verification.update({
        where: { id: verification.id },
        data: { attemptCount: { increment: 1 } },
      });
      res.status(400).json({ error: 'Invalid code', message: 'Login code is incorrect.' });
      return;
    }

    await prisma.verification.update({
      where: { id: verification.id },
      data: { isUsed: true },
    });

    const user = await prisma.user.findUniqueOrThrow({
      where: { id: verification.userId! },
      select: { id: true, name: true, email: true, emailVerified: true, image: true, role: true },
    });

    const { token, jti, expiresAt } = signToken({ sub: user.id, email: user.email, role: user.role });
    const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.socket?.remoteAddress ?? null;
    const userAgent = req.headers['user-agent'] ?? null;

    await prisma.session.create({
      data: {
        token: jti,
        expiresAt,
        userId: user.id,
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
      },
    });

    setAuthCookie(res, token, expiresAt);
    res.status(200).json({
      message: 'Signed in successfully.',
      user: toSafeUser(user),
    });
  } catch (err) {
    console.error('[auth] verifyLogin error:', err);
    res.status(500).json({ error: 'Verification failed', message: 'Something went wrong. Please try again.' });
  }
}

export async function resendOtp(req: Request, res: Response): Promise<void> {
  try {
    const parsed = resendOtpSchema.safeParse(req.body);
    if (!parsed.success) {
      validationError(res, parsed);
      return;
    }

    const { email, type } = parsed.data as ResendOtpBody;

    if (type === 'REGISTER') {
      const user = await prisma.user.findFirst({
        where: { email, deletedAt: null, emailVerified: false },
        select: { id: true },
      });
      if (!user) {
        res.status(400).json({
          error: 'Cannot resend',
          message: 'No pending email verification for this address. Sign up first or use a different email.',
        });
        return;
      }
      const otp = generateOtp();
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);
      await prisma.verification.create({
        data: {
          identifier: email,
          value: otp,
          type: OtpType.REGISTER,
          expiresAt,
          userId: user.id,
        },
      });
      await sendOtp({ to: email, type: 'REGISTER', otp });
      res.status(200).json({
        message: 'A new verification code has been sent to your email.',
        email,
      });
      return;
    }

    if (type === 'LOGIN') {
      const user = await prisma.user.findFirst({
        where: { email, deletedAt: null },
        select: { id: true },
      });
      if (!user) {
        res.status(400).json({
          error: 'Cannot resend',
          message: 'No account found for this email. Sign up or sign in first.',
        });
        return;
      }
      const otp = generateOtp();
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);
      await prisma.verification.create({
        data: {
          identifier: email,
          value: otp,
          type: OtpType.LOGIN,
          expiresAt,
          userId: user.id,
        },
      });
      await sendOtp({ to: email, type: 'LOGIN', otp });
      res.status(200).json({
        message: 'A new login code has been sent to your email.',
        email,
      });
      return;
    }
  } catch (err) {
    console.error('[auth] resendOtp error:', err);
    res.status(500).json({ error: 'Resend failed', message: 'Something went wrong. Please try again.' });
  }
}

export async function getMe(req: Request, res: Response): Promise<void> {
  try {
    if (!req.auth) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }
    const user = await prisma.user.findFirst({
      where: { id: req.auth.sub, deletedAt: null },
      select: { id: true, name: true, email: true, emailVerified: true, image: true, role: true },
    });
    if (!user) {
      res.status(404).json({ error: 'Not found', message: 'User not found.' });
      return;
    }
    res.status(200).json({ user: toSafeUser(user) });
  } catch (err) {
    console.error('[auth] getMe error:', err);
    res.status(500).json({ error: 'Server error', message: 'Something went wrong.' });
  }
}

export async function signout(req: Request, res: Response): Promise<void> {
  try {
    const token = getBearerToken(req);
    if (!token) {
      res.status(400).json({
        error: 'Missing token',
        message: 'Provide your session token in the Authorization header (Bearer <token>) or in the request body as { "token": "<token>" }.',
      });
      return;
    }

    let payload: { jti: string };
    try {
      payload = verifyToken(token);
    } catch {
      res.status(401).json({
        error: 'Invalid or expired token',
        message: 'Your session token is invalid or has expired. Sign in again.',
      });
      return;
    }

    await prisma.session.deleteMany({ where: { token: payload.jti } });

    clearAuthCookie(res);
    res.status(204).send();
  } catch (err) {
    console.error('[auth] signout error:', err);
    res.status(500).json({ error: 'Sign out failed', message: 'Something went wrong. Please try again.' });
  }
}
