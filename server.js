const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");

// Setup Express and HTTP
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static("public"));

// ✅ MySQL Connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",        // change if needed
  password: "",        // change if you have a MySQL password
  database: "chat_app"
});

db.connect((err) => {
  if (err) throw err;
  console.log("✅ Connected to MySQL database");
});

// 🧾 Register endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).send("Missing username or password");

  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = "INSERT INTO users (username, password) VALUES (?, ?)";

  db.query(sql, [username, hashedPassword], (err) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY")
        return res.status(400).send("Username already exists");
      return res.status(500).send("Database error");
    }
    res.send("User registered successfully!");
  });
});

// 🔑 Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (err) return res.status(500).send("Database error");
    if (results.length === 0) return res.status(400).send("User not found");

    const user = results[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).send("Invalid password");

    res.send("Login successful");
  });
});

// 🗨️ Store connected users
let onlineUsers = {};

// Socket.IO for real-time chat
io.on("connection", (socket) => {
  console.log("🔌 New client connected");

  socket.on("authenticate", (username) => {
    onlineUsers[username] = socket.id;
    console.log(`${username} is online`);
  });

  socket.on("private_message", ({ from, to, message }) => {
    const receiverSocket = onlineUsers[to];
    if (receiverSocket) {
      io.to(receiverSocket).emit("receive_message", { from, message });
    }
  });

  socket.on("disconnect", () => {
    for (let user in onlineUsers) {
      if (onlineUsers[user] === socket.id) {
        console.log(`${user} disconnected`);
        delete onlineUsers[user];
        break;
      }
    }
  });
});

server.listen(3000, () => {
  console.log("🚀 Server running on http://localhost:3000");
});
