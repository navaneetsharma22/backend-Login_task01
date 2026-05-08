const rateLimit = require("express-rate-limit");

const createLimiter = (max) =>
  rateLimit({
    windowMs: 5 * 60 * 1000,
    max,
    message: "Too many requests, try again later",
    standardHeaders: true,
    legacyHeaders: false,
  });

const registerLimiter = createLimiter(20);
const verifyOtpLimiter = createLimiter(30);
const loginOtpLimiter = createLimiter(20);
const verifyLoginOtpLimiter = createLimiter(30);

module.exports = {
  registerLimiter,
  verifyOtpLimiter,
  loginOtpLimiter,
  verifyLoginOtpLimiter,
};