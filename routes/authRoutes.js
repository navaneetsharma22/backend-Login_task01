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

const {
  registerLimiter,
  verifyOtpLimiter,
  loginOtpLimiter,
  verifyLoginOtpLimiter,
} = require("../middleware/rateLimiter");

//  Register + OTP
router.post("/register", registerLimiter, register);
router.post("/verify-otp", verifyOtpLimiter, verifyOtp);
router.post("/set-password", setPassword);

//  Login with Password
router.post("/login-password", loginWithPassword);

//  Login with OTP
router.post("/login-otp", loginOtpLimiter, loginOtp);
router.post("/verify-login-otp", verifyLoginOtpLimiter, verifyLoginOtp);

module.exports = router;