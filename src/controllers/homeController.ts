import type { Request, Response } from 'express';

export function getHome(_req: Request, res: Response): void {
   res.send('Hello, TypeScript with Express!');
}
