const express = require("express");
const router = express.Router();

const {
  register,
  verifyOtp,
  setPassword,
  loginWithPassword,
  loginOtp,
  verifyLoginOtp,
} = require("../controllers/authController");

const limiter = require("../middleware/rateLimiter");

//  Register + OTP
router.post("/register", limiter, register);
router.post("/verify-otp", limiter, verifyOtp);
router.post("/set-password", setPassword);

//  Login with Password
router.post("/login-password", loginWithPassword);

//  Login with OTP
router.post("/login-otp", limiter, loginOtp);
router.post("/verify-login-otp", limiter, verifyLoginOtp);

module.exports = router;