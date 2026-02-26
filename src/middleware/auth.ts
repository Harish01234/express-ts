import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../lib/jwt.js';
import { prisma } from '../lib/prisma.js';

const AUTH_COOKIE_NAME = 'auth_token';

function getToken(req: Request): string | undefined {
  const fromCookie = req.cookies?.[AUTH_COOKIE_NAME];
  if (typeof fromCookie === 'string' && fromCookie.trim()) return fromCookie.trim();
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) return auth.slice(7).trim();
  const body = req.body as { token?: string } | undefined;
  return typeof body?.token === 'string' ? body.token.trim() : undefined;
}

/**
 * Requires a valid JWT and an existing, non-expired session.
 * Sets req.auth (sub, email, role, jti); sends 401 otherwise.
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const token = getToken(req);
    if (!token) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required. Provide a valid token in the Authorization header (Bearer), cookie, or body.',
      });
      return;
    }

    const payload = verifyToken(token);

    const session = await prisma.session.findFirst({
      where: {
        token: payload.jti,
        expiresAt: { gt: new Date() },
      },
      select: { userId: true },
    });

    if (!session || session.userId !== payload.sub) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Session invalid or expired. Sign in again.',
      });
      return;
    }

    req.auth = payload;
    next();
  } catch {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired token. Sign in again.',
    });
  }
}

/**
 * Optional auth: if a valid token is present, sets req.auth; otherwise continues without it.
 */
export async function optionalAuth(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const token = getToken(req);
    if (!token) {
      next();
      return;
    }
    const payload = verifyToken(token);
    const session = await prisma.session.findFirst({
      where: { token: payload.jti, expiresAt: { gt: new Date() } },
      select: { userId: true },
    });
    if (session && session.userId === payload.sub) {
      req.auth = payload;
    }
    next();
  } catch {
    next();
  }
}
