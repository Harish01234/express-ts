import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';

import indexRoutes from './routes/index.js';
import authRoutes from './routes/auth.js';

const app = express();

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map((o) => o.trim()).filter(Boolean);
app.use(
  cors({
    origin: allowedOrigins?.length ? allowedOrigins : true,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(express.urlencoded({ extended: true }));

app.use('/', indexRoutes);
app.use('/auth', authRoutes);

app.use((_req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error', message: 'Something went wrong.' });
});

export default app;
