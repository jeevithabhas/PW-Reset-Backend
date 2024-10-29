const User = require('../models/User');
const transporter = require('../config/nodemailer');
const generateToken = require('../utils/generateToken');
const bcrypt = require('bcryptjs');

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  const resetToken = generateToken();
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 3600000; // 1 hour expiration
  await user.save();

  // Directly include the reset token in the email
  await transporter.sendMail({
    to: user.email,
    subject: 'Password Reset Request',
    html: `<p>Your password reset token is: <strong>${resetToken}</strong></p>
           <p>Use this token to reset your password.</p>`,
  });

  res.json({ message: 'Reset token sent to email' });
};


exports.resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

  user.password = await bcrypt.hash(password, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();

  res.json({ message: 'Password updated successfully' });
};
