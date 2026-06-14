require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, trim: true },
  password: String,
  lastSeen: { type: Date, default: Date.now },
  location: { lat: Number, lng: Number, accuracy: Number, updatedAt: Date }
});

const messageSchema = new mongoose.Schema({
  from: String, to: String, text: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Fields required' });
    if (await User.findOne({ username })) return res.status(400).json({ error: 'Username taken' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users', authMiddleware, async (req, res) => {
  const users = await User.find({ username: { $ne: req.user.username } }).select('username lastSeen location');
  res.json(users);
});

app.get('/api/messages/:otherUser', authMiddleware, async (req, res) => {
  const me = req.user.username;
  const other = req.params.otherUser;
  const msgs = await Message.find({
    $or: [{ from: me, to: other }, { from: other, to: me }]
  }).sort({ createdAt: 1 }).limit(100);
  res.json(msgs);
});

const onlineUsers = {};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers[username] = socket.id;
  io.emit('user_online', { username });

  socket.on('send_message', async ({ to, text }) => {
    if (!text?.trim()) return;
    const msg = await Message.create({ from: username, to, text: text.trim() });
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('receive_message', { from: username, to, text: msg.text, createdAt: msg.createdAt });
    socket.emit('message_sent', { from: username, to, text: msg.text, createdAt: msg.createdAt });
  });

  socket.on('location_update', async ({ to, lat, lng, accuracy }) => {
    await User.findByIdAndUpdate(socket.user.id, {
      location: { lat, lng, accuracy, updatedAt: new Date() }, lastSeen: new Date()
    });
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('location_received', { from: username, lat, lng, accuracy, updatedAt: new Date() });
  });

  socket.on('disconnect', () => {
    delete onlineUsers[username];
    io.emit('user_offline', { username });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
