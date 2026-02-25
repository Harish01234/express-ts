import nodemailer from 'nodemailer';
import { z } from 'zod';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Load .env from project root (works when run from dist/lib or src/lib)
config({ path: path.resolve(__dirname, '../../.env') });


const OTP_LENGTH = 6;

export const OtpType = {
  REGISTER: 'REGISTER',
  LOGIN: 'LOGIN',
  RESET_PASSWORD: 'RESET_PASSWORD',
} as const;

export type OtpTypeValue = (typeof OtpType)[keyof typeof OtpType];

const sendOtpSchema = z.object({
  to: z.string().email(),
  type: z.enum([OtpType.REGISTER, OtpType.LOGIN, OtpType.RESET_PASSWORD]),
  otp: z
    .string()
    .length(OTP_LENGTH, `OTP must be exactly ${OTP_LENGTH} digits`)
    .regex(/^\d+$/, 'OTP must contain only digits'),
});

export type SendOtpParams = z.infer<typeof sendOtpSchema>;

const subjectByType: Record<OtpTypeValue, string> = {
  [OtpType.REGISTER]: 'Verify your email – registration',
  [OtpType.LOGIN]: 'Your login code',
  [OtpType.RESET_PASSWORD]: 'Reset your password',
};

const titleByType: Record<OtpTypeValue, string> = {
  [OtpType.REGISTER]: 'Verify your email',
  [OtpType.LOGIN]: 'Login code',
  [OtpType.RESET_PASSWORD]: 'Reset password',
};

const bodyByType: Record<OtpTypeValue, string> = {
  [OtpType.REGISTER]:
    'Use the code below to complete your registration. If you didn’t request this, you can ignore this email.',
  [OtpType.LOGIN]:
    'Use the code below to sign in. If you didn’t request this, please secure your account.',
  [OtpType.RESET_PASSWORD]:
    'Use the code below to reset your password. If you didn’t request this, you can ignore this email.',
};

function getTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT) || 587;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error(
      'Missing SMTP config: set SMTP_HOST, SMTP_USER, SMTP_PASS in .env'
    );
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });
}

function buildHtml(type: OtpTypeValue, otp: string): string {
  const title = titleByType[type];
  const body = bodyByType[type];
  return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
  <h1 style="font-size: 1.25rem; margin-bottom: 8px;">${title}</h1>
  <p style="color: #374151; margin-bottom: 24px;">${body}</p>
  <p style="font-size: 1.5rem; font-weight: 700; letter-spacing: 0.25em; margin: 16px 0;">${otp}</p>
  <p style="font-size: 0.875rem; color: #6b7280;">This code expires in 10 minutes.</p>
</body>
</html>`.trim();
}

/**
 * Send an OTP email. You provide the 6-digit OTP; validates to, type, and OTP with Zod.
 */
export async function sendOtp(
  params: SendOtpParams
): Promise<{ success: true; messageId: string }> {
  const parsed = sendOtpSchema.safeParse(params);
  if (!parsed.success) {
    const first = parsed.error.flatten().fieldErrors;
    const msg = Object.entries(first)
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
      .join('; ');
    console.error('[sendmail] Validation failed:', msg);
    throw new Error(`Validation failed: ${msg}`);
  }

  const { to, type, otp } = parsed.data;
  console.log(`[sendmail] Sending OTP email to ${to} (type: ${type})`);

  const transporter = getTransporter();
  const from = process.env.SMTP_USER ?? 'noreply@localhost';
  const subject = subjectByType[type];
  const html = buildHtml(type, otp);
  const text = `${titleByType[type]}\n\n${bodyByType[type]}\n\nYour code: ${otp}\n\nThis code expires in 10 minutes.`;

  try {
    const info = await transporter.sendMail({
      from: `"${process.env.APP_NAME ?? 'App'}" <${from}>`,
      to,
      subject,
      text,
      html,
    });
    console.log(`[sendmail] Mail sent to ${to} (messageId: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[sendmail] Failed to send mail to ${to}:`, message);
    throw err;
  }
}

/**
 * Generate a random 6-digit OTP string (optional helper; you can pass your own OTP to sendOtp).
 */
export function generateOtp(): string {
  const min = 10 ** (OTP_LENGTH - 1);
  const max = 10 ** OTP_LENGTH - 1;
  const n = Math.floor(min + Math.random() * (max - min + 1));
  return String(n);
}

sendOtp({
  to: 'harish@visolutionz.com',
  type: OtpType.LOGIN,
  otp: '123456'
});