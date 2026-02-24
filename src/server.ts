import app from './app.js';

const port = process.env['PORT'] ?? 3001;

const server = app.listen(port, () => {
   console.log(`Server running at http://localhost:${port}`);
});

server.on('error', (err: Error) => {
   console.error('Server error:', err);
   process.exit(1);
});
