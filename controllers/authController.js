const User = require("../models/User");
const Otp = require("../models/Otp");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const generateOtp = require("../utils/generateOtp");
const sendEmail = require("../utils/sendEmail");
const sendSms = require("../utils/sendSms");

const normalizeValue = (value) => {
  if (typeof value !== "string") return undefined;

  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
};

const buildContactFilters = ({ email, phone }) => {
  const filters = [];

  if (email) filters.push({ email });
  if (phone) filters.push({ phone });

  return filters;
};

const sendOtpThroughAvailableChannels = async ({ email, phone, otp, subject }) => {
  const deliveryErrors = [];
  let delivered = false;

  if (email) {
    try {
      await sendEmail(email, subject, `Your OTP is: ${otp}`);
      delivered = true;
    } catch (error) {
      deliveryErrors.push(`email: ${error.message}`);
    }
  }

  if (phone) {
    try {
      await sendSms(phone, otp);
      delivered = true;
    } catch (error) {
      deliveryErrors.push(`phone: ${error.message}`);
    }
  }

  return { delivered, deliveryErrors };
};

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

exports.register = async (req, res) => {
  try {
    const name = normalizeValue(req.body.name);
    const email = normalizeValue(req.body.email);
    const phone = normalizeValue(req.body.phone);
    const contactFilters = buildContactFilters({ email, phone });

    if (!name) {
      return res.status(400).json({ message: "Name is required" });
    }

    if (contactFilters.length === 0) {
      return res.status(400).json({ message: "Email or phone is required" });
    }

    let user = await User.findOne({ $or: contactFilters });

    if (user && user.isVerified) {
      return res.status(400).json({ message: "User already exists" });
    }

    await Otp.deleteMany({ $or: contactFilters });

    const otp = generateOtp();

    await Otp.create({
      email,
      phone,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    const { delivered, deliveryErrors } = await sendOtpThroughAvailableChannels({
      email,
      phone,
      otp,
      subject: "Your OTP Code",
    });

    if (!delivered) {
      await Otp.deleteMany({ $or: contactFilters });

      return res.status(500).json({
        message:
          deliveryErrors.length > 0
            ? `Failed to send OTP. ${deliveryErrors.join(" | ")}`
            : "Failed to send OTP",
      });
    }

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

exports.verifyOtp = async (req, res) => {
  try {
    const email = normalizeValue(req.body.email);
    const phone = normalizeValue(req.body.phone);
    const otp = normalizeValue(req.body.otp);
    const contactFilters = buildContactFilters({ email, phone });

    if (contactFilters.length === 0 || !otp) {
      return res.status(400).json({ message: "Email or phone and OTP are required" });
    }

    const otpRecord = await Otp.findOne({
      $or: contactFilters,
      otp,
    });

    if (!otpRecord) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    const user = await User.findOne({ $or: contactFilters });

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

exports.setPassword = async (req, res) => {
  try {
    const email = normalizeValue(req.body.email);
    const password = normalizeValue(req.body.password);

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

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

exports.loginWithPassword = async (req, res) => {
  try {
    const email = normalizeValue(req.body.email);
    const password = normalizeValue(req.body.password);

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

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

exports.loginOtp = async (req, res) => {
  try {
    const email = normalizeValue(req.body.email);
    const phone = normalizeValue(req.body.phone);
    const contactFilters = buildContactFilters({ email, phone });

    if (contactFilters.length === 0) {
      return res.status(400).json({ message: "Email or phone is required" });
    }

    const user = await User.findOne({ $or: contactFilters });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    await Otp.deleteMany({ $or: contactFilters });

    const otp = generateOtp();

    await Otp.create({
      email,
      phone,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    const { delivered, deliveryErrors } = await sendOtpThroughAvailableChannels({
      email,
      phone,
      otp,
      subject: "Login OTP",
    });

    if (!delivered) {
      await Otp.deleteMany({ $or: contactFilters });

      return res.status(500).json({
        message:
          deliveryErrors.length > 0
            ? `Failed to send OTP. ${deliveryErrors.join(" | ")}`
            : "Failed to send OTP",
      });
    }

    res.json({ message: "OTP sent for login" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.verifyLoginOtp = async (req, res) => {
  try {
    const email = normalizeValue(req.body.email);
    const phone = normalizeValue(req.body.phone);
    const otp = normalizeValue(req.body.otp);
    const contactFilters = buildContactFilters({ email, phone });

    if (contactFilters.length === 0 || !otp) {
      return res.status(400).json({ message: "Email or phone and OTP are required" });
    }

    const otpRecord = await Otp.findOne({
      $or: contactFilters,
      otp,
    });

    if (!otpRecord) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    const user = await User.findOne({ $or: contactFilters });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    await Otp.deleteOne({ _id: otpRecord._id });

    res.json({
      token: generateToken(user._id),
      user,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
