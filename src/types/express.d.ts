declare global {
  namespace Express {
    interface Request {
      auth?: {
        sub: string;
        email: string;
        role: string;
        jti: string;
      };
    }
  }
}

export {};
