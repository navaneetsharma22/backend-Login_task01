const nodemailer = require("nodemailer");

const sendEmail = async (to, subject, text) => {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error("Email credentials (EMAIL_USER/EMAIL_PASS) are missing in .env");
    }

    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true, // Use SSL
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      // Shorter timeouts to avoid keeping the user waiting too long if it fails
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 12000,
    });

    // Verify connection configuration
    await transporter.verify();
    console.log("SMTP server is ready to take our messages");

    const info = await transporter.sendMail({
      from: `"Support" <${process.env.EMAIL_USER}>`,
      to: to,
      subject: subject,
      text: text,
    });

    console.log("Email sent successfully:", info.messageId);
    return true;
  } catch (error) {
    console.error("Critical Mail Error:", error.message);
    if (error.code === 'EAUTH') {
      console.error("Authentication failed. Please check your EMAIL_PASS (must be an App Password).");
    }
    throw error;
  }
};

module.exports = sendEmail;