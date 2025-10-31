import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { requireAuth, requireRole } from './jwtMiddleware.js';
const app = express();
app.use(cors());
app.use(express.json());
const limiter = rateLimit({ windowMs: 60_000, max: 60 });
app.use(limiter);
app.get('/', (_, res) => res.json({ name: 'Resource API', status: 'ok' }));
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ id: req.user.sub, email: req.user.email, role: req.user.role });
});
app.get('/api/admin/secret', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ flag: 'TOP_SECRET_FOR_ADMINS' });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Resource API listening on :${PORT}`));