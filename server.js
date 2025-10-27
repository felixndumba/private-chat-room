require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ------------------ MIDDLEWARES ------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({
  secret: "secret",
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// ------------------ DATABASE ------------------
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "chat_app"
});

// ------------------ USER REGISTRATION ------------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed], (err) => {
    if (err) return res.status(500).send("User already exists or DB error");
    res.send("✅ Registration successful!");
  });
});

// ------------------ USER LOGIN ------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (err || results.length === 0) return res.send("User not found");
    const match = await bcrypt.compare(password, results[0].password);
    if (!match) return res.send("Invalid password");
    req.session.user = results[0];
    res.send("Login successful");
  });
});

// ------------------ GOOGLE OAUTH ------------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  const username = profile.emails[0].value;
  db.query("SELECT * FROM users WHERE username = ?", [username], (err, rows) => {
    if (rows.length === 0) {
      db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, "oauth"], () => {
        return done(null, { username });
      });
    } else {
      return done(null, { username });
    }
  });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    req.session.user = req.user;
    res.redirect(`/chat.html?user=${encodeURIComponent(req.user.username)}`);
  }
);

// ------------------ SERVE PAGES ------------------
app.get("/", (req, res) => res.sendFile(__dirname + "/login.html"));
app.get("/chat.html", (req, res) => res.sendFile(__dirname + "/chat.html"));

// ------------------ SOCKET.IO ------------------
const onlineUsers = {}; // username -> Set of socket IDs

io.on("connection", (socket) => {
  console.log("✅ User connected");

  // Authenticate user
  socket.on("authenticate", (username) => {
    socket.username = username;
    if (!onlineUsers[username]) onlineUsers[username] = new Set();
    onlineUsers[username].add(socket.id);
    console.log(`${username} connected. Total sockets: ${onlineUsers[username].size}`);
  });

  // Handle private messages
  socket.on("private_message", ({ from, to, message }) => {
    // Save message to DB
    db.query(
      `INSERT INTO messages (sender_id, receiver_id, message)
       VALUES ((SELECT id FROM users WHERE username = ?),
               (SELECT id FROM users WHERE username = ?),
               ?)`,
      [from, to, message]
    );

    // Send message to recipient's socket(s)
    if (onlineUsers[to]) {
      onlineUsers[to].forEach(socketId => {
        io.to(socketId).emit("receive_message", { from, message });
      });
    }
  });

  // Handle disconnection
  socket.on("disconnect", () => {
    if (socket.username && onlineUsers[socket.username]) {
      onlineUsers[socket.username].delete(socket.id);
      if (onlineUsers[socket.username].size === 0) delete onlineUsers[socket.username];
    }
    console.log("❌ User disconnected");
  });
});

// ------------------ GET CHAT HISTORY ------------------
app.get("/messages/:user1/:user2", (req, res) => {
  const { user1, user2 } = req.params;
  db.query(
    `SELECT m.message, u1.username AS sender, u2.username AS receiver, m.created_at 
     FROM messages m
     JOIN users u1 ON m.sender_id = u1.id
     JOIN users u2 ON m.receiver_id = u2.id
     WHERE (u1.username = ? AND u2.username = ?) OR (u1.username = ? AND u2.username = ?)
     ORDER BY m.created_at`,
    [user1, user2, user2, user1],
    (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results);
    }
  );
});

// ------------------ START SERVER ------------------
server.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));
