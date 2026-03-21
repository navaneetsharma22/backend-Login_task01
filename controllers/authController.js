const User = require("../models/User");
const Otp = require("../models/Otp");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const generateOtp = require("../utils/generateOtp");
const sendEmail = require("../utils/sendEmail");
const sendSms = require("../utils/sendSms");

// 🔑 Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

///////////////////////////////////////////////////////////
// 1. REGISTER (Send OTP)
///////////////////////////////////////////////////////////
exports.register = async (req, res) => {
  try {
    const { name, email, phone } = req.body;

    // check existing user
    let user = await User.findOne({
      $or: [{ email }, { phone }],
    });

    // ❌ If already verified → block
    if (user && user.isVerified) {
      return res.status(400).json({ message: "User already exists" });
    }

    // 🔥 delete old OTPs (prevent spam)
    await Otp.deleteMany({
      $or: [{ email }, { phone }],
    });

    // generate OTP
    const otp = generateOtp();

    // save OTP
    await Otp.create({
      email,
      phone,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 min
    });

    // 🔥 send OTP FIRST
    try {
      if (email) await sendEmail(email, "Your OTP Code", `Your OTP is: ${otp}`);
      if (phone) await sendSms(phone, otp);
    } catch (err) {
      return res.status(500).json({ message: "Failed to send OTP" });
    }

    // 🔥 create user only if not exists
    if (!user) {
      user = await User.create({
        name,
        email,
        phone,
        isVerified: false,
      });
    }

    res.json({ message: "OTP sent successfully" });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

///////////////////////////////////////////////////////////
// 2. VERIFY OTP (Registration)
///////////////////////////////////////////////////////////
exports.verifyOtp = async (req, res) => {
  try {
    const { email, phone, otp } = req.body;

    const otpRecord = await Otp.findOne({
      $or: [{ email }, { phone }],
      otp,
    });

    if (!otpRecord) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    const user = await User.findOne({
      $or: [{ email }, { phone }],
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    user.isVerified = true;
    await user.save();

    await Otp.deleteOne({ _id: otpRecord._id });

    res.json({ message: "OTP verified successfully" });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

///////////////////////////////////////////////////////////
// 3. SET PASSWORD
///////////////////////////////////////////////////////////
exports.setPassword = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user || !user.isVerified) {
      return res.status(400).json({ message: "User not verified" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password set successfully" });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

///////////////////////////////////////////////////////////
// 4. LOGIN (Email + Password)
///////////////////////////////////////////////////////////
exports.loginWithPassword = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (!user.password) {
      return res.status(400).json({ message: "Set password first" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    res.json({
      token: generateToken(user._id),
      user,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

///////////////////////////////////////////////////////////
// 5. LOGIN OTP (Send OTP)
///////////////////////////////////////////////////////////
exports.loginOtp = async (req, res) => {
  try {
    const { email, phone } = req.body;

    const user = await User.findOne({
      $or: [{ email }, { phone }],
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    await Otp.deleteMany({
      $or: [{ email }, { phone }],
    });

    const otp = generateOtp();

    await Otp.create({
      email,
      phone,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    if (email) await sendEmail(email, "Login OTP", `Your OTP is: ${otp}`);
    if (phone) await sendSms(phone, otp);

    res.json({ message: "OTP sent for login" });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

///////////////////////////////////////////////////////////
// 6. VERIFY LOGIN OTP
///////////////////////////////////////////////////////////
exports.verifyLoginOtp = async (req, res) => {
  try {
    const { email, phone, otp } = req.body;

    const otpRecord = await Otp.findOne({
      $or: [{ email }, { phone }],
      otp,
    });

    if (!otpRecord) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    const user = await User.findOne({
      $or: [{ email }, { phone }],
    });

    await Otp.deleteOne({ _id: otpRecord._id });

    res.json({
      token: generateToken(user._id),
      user,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};