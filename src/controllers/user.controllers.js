const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");
const jwt = require("jsonwebtoken");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const {
    email,
    password,
    firstName,
    lastName,
    country,
    image,
    isVerified,
    frontBaseUrl,
  } = req.body;
  const encriptedPassword = await bcrypt.hash(password, 10);
  const result = await User.create({
    email,
    password: encriptedPassword,
    firstName,
    lastName,
    country,
    image,
    isVerified,
  });

  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;
  await EmailCode.create({ code, userId: result.id });
  await sendEmail({
    to: email, // Email del receptor
    subject: "Verificacion de email", // asunto
    html: ` <h1> llego un correo de ${firstName} ${lastName}</h1>
                <br>
                <a href= '${link}'>${link}</a> 
          `,
  });

  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.update(req.body, {
    where: { id },
    returning: true,
  });
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const VerifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ message: "Code not found" });
  const user = await User.findByPk(emailCode.userId);
  user.isVerified = true;
  await user.save();
  await emailCode.destroy();
  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ message: "nvalid credentials" });

  const userVerify = user.isVerified;
  if (!userVerify)
    return res.status(401).json({ message: "User not verified" });
  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });
  return res.json({ user, token });
});
const getMe = catchError(async (req, res) => {
  const user = req.user;
  return res.json(user);
});
const resetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(401).json({ message: "Invalid email" });
  }
  const code = require("crypto").randomBytes(32).toString("hex");

  const link = `${frontBaseUrl}/auth/reset_password/${code}`;
  await EmailCode.create({ code, userId: user.id });
  await sendEmail({
    to: email, // Email del receptor
    subject: "Reset de password", // asunto
    html: ` <h1> you received an email to change your password</h1>
                <br>
                <a href= '${link}'>${link}</a> 
          `,
  });
  return res.json(user);
});
const resetPasswordCode = catchError(async (req, res) => {
  const { password } = req.body;
  console.log(password);
  const { code } = req.params;
  console.log(code);
  const codeEmail = await EmailCode.findOne({ where: { code } });
  // console.log(codeEmail)
  if (!codeEmail) {
    return res.status(401).json({ message: "Invalid code" });
  }
  const newPassword = await bcrypt.hash(password, 10);
  const user = await User.findByPk(codeEmail.userId);
  console.log(user);
  user.password = newPassword;
  await user.save();
  await codeEmail.destroy();
  return res.json(user);
});
module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  VerifyCode,
  getMe,
  login,
  resetPassword,
  resetPasswordCode,
};
