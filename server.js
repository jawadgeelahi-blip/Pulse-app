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
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// ─── SCHEMAS ───────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, trim: true },
  password: String,
  bio: { type: String, default: '' },
  profilePic: { type: String, default: '' },
  lastSeen: { type: Date, default: Date.now },
  location: { lat: Number, lng: Number, accuracy: Number, updatedAt: Date }
});

const messageSchema = new mongoose.Schema({
  from: String, to: String, text: String,
  seen: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const friendSchema = new mongoose.Schema({
  from: String,
  to: String,
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const callSchema = new mongoose.Schema({
  from: String, to: String,
  type: { type: String, enum: ['voice', 'video'], default: 'voice' },
  status: { type: String, enum: ['missed', 'answered', 'rejected'], default: 'missed' },
  duration: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Friend = mongoose.model('Friend', friendSchema);
const Call = mongoose.model('Call', callSchema);

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Fields required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username too short' });
    if (password.length < 4) return res.status(400).json({ error: 'Password too short' });
    if (await User.findOne({ username })) return res.status(400).json({ error: 'Username taken' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username, profilePic: user.profilePic, bio: user.bio });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ─── USER ROUTES ──────────────────────────────────────────────────
app.get('/api/users/search', auth, async (req, res) => {
  const q = req.query.q || '';
  const users = await User.find({
    username: { $ne: req.user.username, $regex: q, $options: 'i' }
  }).select('username profilePic bio lastSeen').limit(20);
  res.json(users);
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

app.put('/api/me', auth, async (req, res) => {
  try {
    const { bio, profilePic, newPassword, currentPassword } = req.body;
    const user = await User.findById(req.user.id);
    if (bio !== undefined) user.bio = bio;
    if (profilePic !== undefined) user.profilePic = profilePic;
    if (newPassword && currentPassword) {
      const valid = await bcrypt.compare(currentPassword, user.password);
      if (!valid) return res.status(400).json({ error: 'Wrong current password' });
      user.password = await bcrypt.hash(newPassword, 10);
    }
    await user.save();
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ─── FRIEND ROUTES ────────────────────────────────────────────────
app.post('/api/friends/request', auth, async (req, res) => {
  try {
    const { to } = req.body;
    const from = req.user.username;
    if (from === to) return res.status(400).json({ error: 'Cannot add yourself' });
    const exists = await Friend.findOne({
      $or: [{ from, to }, { from: to, to: from }]
    });
    if (exists) return res.status(400).json({ error: 'Request already exists' });
    const friend = await Friend.create({ from, to });
    res.json({ success: true, friend });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/friends/respond', auth, async (req, res) => {
  try {
    const { from, status } = req.body;
    const to = req.user.username;
    await Friend.findOneAndUpdate({ from, to, status: 'pending' }, { status });
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/friends', auth, async (req, res) => {
  const me = req.user.username;
  const accepted = await Friend.find({
    status: 'accepted',
    $or: [{ from: me }, { to: me }]
  });
  const friends = accepted.map(f => f.from === me ? f.to : f.from);
  const users = await User.find({ username: { $in: friends } }).select('username profilePic bio lastSeen');
  res.json(users);
});

app.get('/api/friends/pending', auth, async (req, res) => {
  const pending = await Friend.find({ to: req.user.username, status: 'pending' });
  res.json(pending);
});

app.get('/api/friends/sent', auth, async (req, res) => {
  const sent = await Friend.find({ from: req.user.username, status: 'pending' });
  res.json(sent);
});

// ─── MESSAGE ROUTES ───────────────────────────────────────────────
app.get('/api/messages/:otherUser', auth, async (req, res) => {
  const me = req.user.username;
  const other = req.params.otherUser;
  const msgs = await Message.find({
    $or: [{ from: me, to: other }, { from: other, to: me }]
  }).sort({ createdAt: 1 }).limit(100);
  await Message.updateMany({ from: other, to: me, seen: false }, { seen: true });
  res.json(msgs);
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ─── CALL ROUTES ─────────────────────────────────────────────────
app.get('/api/calls', auth, async (req, res) => {
  const me = req.user.username;
  const calls = await Call.find({
    $or: [{ from: me }, { to: me }]
  }).sort({ createdAt: -1 }).limit(50);
  res.json(calls);
});

// ─── SOCKET.IO ────────────────────────────────────────────────────
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
  console.log('🟢 ' + username + ' connected');

  socket.on('send_message', async ({ to, text }) => {
    if (!text?.trim()) return;
    const msg = await Message.create({ from: username, to, text: text.trim() });
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('receive_message', {
      _id: msg._id, from: username, to, text: msg.text, createdAt: msg.createdAt
    });
    socket.emit('message_sent', {
      _id: msg._id, from: username, to, text: msg.text, createdAt: msg.createdAt
    });
  });

  socket.on('msg_seen', ({ to }) => {
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('msg_seen', { from: username });
  });

  socket.on('location_update', async ({ to, lat, lng, accuracy }) => {
    await User.findByIdAndUpdate(socket.user.id, {
      location: { lat, lng, accuracy, updatedAt: new Date() },
      lastSeen: new Date()
    });
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('location_received', { from: username, lat, lng, accuracy });
  });

  socket.on('friend_request', ({ to }) => {
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('friend_request_received', { from: username });
  });

  socket.on('friend_accepted', ({ to }) => {
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('friend_accepted', { from: username });
  });

  socket.on('call_user', ({ to, type }) => {
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('incoming_call', { from: username, type });
  });

  socket.on('call_accepted', ({ to }) => {
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('call_accepted', { from: username });
  });

  socket.on('call_rejected', ({ to }) => {
    const rid = onlineUsers[to];
    if (rid) io.to(rid).emit('call_rejected', { from: username });
  });

  socket.on('disconnect', () => {
    delete onlineUsers[username];
    io.emit('user_offline', { username });
    User.findByIdAndUpdate(socket.user.id, { lastSeen: new Date() }).exec();
    console.log('🔴 ' + username + ' disconnected');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('🚀 Server on port ' + PORT));
