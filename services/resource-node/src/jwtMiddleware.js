import jwt from 'jsonwebtoken';
export function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({ error: 'token ausente' });
  }
  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET, { audience: 'tokensecure' });
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'token inválido' });
  }
}
export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}