import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN ?? '7d';
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction && (!JWT_SECRET || JWT_SECRET.length < 32)) {
  throw new Error('Production requires JWT_SECRET (at least 32 characters) in .env');
}
if (!isProduction && (!JWT_SECRET || JWT_SECRET.length < 32)) {
  console.warn('[jwt] JWT_SECRET should be set and at least 32 characters for production.');
}

export type JwtPayload = {
  sub: string;
  email: string;
  role: string;
  jti: string;
  iat?: number;
  exp?: number;
};

export type SignTokenResult = {
  token: string;
  jti: string;
  expiresAt: Date;
};

export function signToken(payload: Omit<JwtPayload, 'iat' | 'exp' | 'jti'>): SignTokenResult {
  const secret = JWT_SECRET ?? 'dev-secret-change-in-production';
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: payload.sub, email: payload.email, role: payload.role, jti },
    secret,
    { expiresIn: JWT_EXPIRES_IN } as jwt.SignOptions
  );
  const decoded = jwt.decode(token) as { exp: number };
  const expiresAt = new Date(decoded.exp * 1000);
  return { token, jti, expiresAt };
}

export function verifyToken(token: string): JwtPayload {
  const secret = JWT_SECRET ?? 'dev-secret-change-in-production';
  const decoded = jwt.verify(token, secret) as JwtPayload;
  if (!decoded.sub || !decoded.email || !decoded.role || !decoded.jti) {
    throw new Error('Invalid token payload');
  }
  return decoded;
}
