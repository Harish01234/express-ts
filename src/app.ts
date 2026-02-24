import express from 'express';
import cors from 'cors';
import helmet from "helmet";

import indexRoutes from './routes/index.js';
import authRoutes from './routes/auth.js';

const app = express();

app.use(cors({ origin: true }));
app.use(express.json());
app.use(helmet());
app.use(express.urlencoded({ extended: true }));

app.use('/', indexRoutes);
app.use('/auth', authRoutes);

export default app;
