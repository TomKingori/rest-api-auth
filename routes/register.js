const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { accessTokenSecret } = require("../config");
const router = express.Router();

const users = Datastore.create("Users.db");

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: The user's name
 *               email:
 *                 type: string
 *                 description: The user's email
 *               password:
 *                 type: string
 *                 description: The user's password
 *               role:
 *                 type: string
 *                 description: The user's role (admin or member)
 *                 example: "admin"
 *           example:
 *             name: "Tom"
 *             email: "tom@gmail.com"
 *             password: "test321"
 *             role: "admin"
 *     responses:
 *       201:
 *         description: User registered successfully
 *       422:
 *         description: Missing required fields
 *       500:
 *         description: Some server error
 */
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(422).json({
        message: "Please fill in all fields (name, email and password)",
      });
    }

    if (await users.findOne({ email: email })) {
      return res
        .status(409)
        .json({ message: `User with email ${email} exists` });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await users.insert({
      name: name,
      email: email,
      password: hashedPassword,
      role: role?.trim() || "member",
    });

    return res
      .status(201)
      .json({ message: "User registered successfully", id: newUser._id });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in a user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: The user's email
 *               password:
 *                 type: string
 *                 description: The user's password
 *           example:
 *             email: "tom@gmail.com"
 *             password: "test321"
 *     responses:
 *       200:
 *         description: User logged in successfully
 *       401:
 *         description: Unauthorized - Invalid email or password
 *       422:
 *         description: Missing required fields
 *       500:
 *         description: Internal server error
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(422).json({
        message: "Please fill in all fields (email and password)",
      });
    }

    const user = await users.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email or Password is invalid" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Email or Password is invalid" });
    }

    const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, {
      subject: "accessApi",
      expiresIn: "1h",
    });

    return res.status(200).json({
      message: "User logged in successfully",
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /verify-login:
 *   get:
 *     summary: Verify the user's login status
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User verification successful
 *       401:
 *         description: Unauthorized - Access token not found, invalid, or expired
 *       500:
 *         description: Internal server error
 */
router.get("/verify-login", verifyAuthentication, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });
    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /admin:
 *   get:
 *     summary: Admin access only route
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Admin access granted
 *       403:
 *         description: Forbidden - Access denied
 *       500:
 *         description: Internal server error
 */
router.get(
  "/admin",
  verifyAuthentication,
  authorize(["admin"]),
  async (req, res) => {
    return res.status(200).json({ message: "Admin access only route" });
  }
);

/**
 * @swagger
 * /member:
 *   get:
 *     summary: Admin and member access only route
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Member access granted
 *       403:
 *         description: Forbidden - Access denied
 *       500:
 *         description: Internal server error
 */
router.get(
  "/member",
  verifyAuthentication,
  authorize(["admin", "member"]),
  async (req, res) => {
    return res
      .status(200)
      .json({ message: "Admin and member access only route" });
  }
);

async function verifyAuthentication(req, res, next) {
  const accessToken = req.headers.authorization?.split(" ")[1];
  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }
  try {
    const decodedAccessToken = jwt.verify(accessToken, accessTokenSecret);
    req.user = { id: decodedAccessToken.userId };
    next();
  } catch (error) {
    return res.status(401).json({ message: "Access token invalid or expired" });
  }
}

function authorize(roles = []) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });

    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

module.exports = router;
