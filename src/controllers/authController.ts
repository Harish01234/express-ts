import type { Request, Response } from 'express';

export function signup(_req: Request, res: Response): void {
   // TODO: signup logic
   res.status(501).json({ message: 'Signup not implemented yet' });
}

export function signin(_req: Request, res: Response): void {
   // TODO: signin logic
   res.status(501).json({ message: 'Signin not implemented yet' });
}

export function signout(_req: Request, res: Response): void {
   // TODO: signout logic
   res.status(501).json({ message: 'Signout not implemented yet' });
}
