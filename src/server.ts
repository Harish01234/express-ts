import 'dotenv/config';
import './lib/jwt.js';
import app from './app.js';

const port = process.env['PORT'] ?? 3001;

const server = app.listen(port, () => {
   console.log(`Server running at http://localhost:${port}`);
});

server.on('error', (err: Error & { code?: string }) => {
   if (err.code === 'EADDRINUSE') {
      console.error(`Port ${port} is already in use. Stop the other process or set PORT to a different number (e.g. PORT=3001).`);
   } else {
      console.error('Server error:', err);
   }
   process.exit(1);
});
