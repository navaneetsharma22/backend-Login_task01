require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");

connectDB();

const app = express();
app.set("trust proxy", 1);

// Middleware
const normalizeOrigin = (url = "") => url.trim().replace(/\/$/, "");

const allowedOrigins = [
  process.env.FRONTEND_URL,
  ...(process.env.FRONTEND_URLS || "").split(",").map((url) => url.trim()),
  "https://frontend-login-task01.vercel.app",

]
  .filter(Boolean)
  .map(normalizeOrigin);


app.use(
  cors({
    origin: (origin, callback) => {
      // DEBUG: See what origin is being sent in your terminal
      if (origin) console.log("CORS Request from Origin:", origin);

      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(normalizeOrigin(origin))) {
        return callback(null, true);
      }

      console.error("CORS Blocked for Origin:", origin);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,

  })
);

app.use(express.json());

// Routes
const authRoutes = require("./routes/authRoutes");
app.use("/api/auth", authRoutes);

// Test route
app.get("/", (req, res) => {
  res.send("API Running...");
});

// Server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});