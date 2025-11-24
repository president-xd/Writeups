const express = require("express");
const fs = require("fs")
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const morgan = require("morgan");

const app = express();
app.use(bodyParser.json());
app.use(morgan())

const db = new sqlite3.Database(":memory:", (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Connected to the in-memory SQlite database.");
});

db.run(
  "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT,role VARCHAR(255))",
  (err) => {
    if (err) {
      return console.error(err.message);
    }
  },
);


app.post("/register", (req, res) => {
  const { username, password } = req.body;


  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (row) {
      return res.status(400).json({ error: "Username already exists" });
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      db.run(
        "INSERT INTO users (username, password,role) VALUES (?, ?,?)",
        [username, hash, "user"],
        function (err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          res.status(201).json({ message: "User registered successfully" });
        },
      );
    });
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (!row) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    bcrypt.compare(password, row.password, (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!result) {
        return res.status(400).json({ error: "Invalid username or password" });
      }

      return res.status(200).json({ username: row.username, id: row.id, role: row.role });
    });
  });
});

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
