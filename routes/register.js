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
 *           example:
 *             name: "Tom"
 *             email: "tom@gmail.com"
 *             password: "test321"
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
    const { name, email, password } = req.body;
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
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "User logged in successfully"
 *                 id:
 *                   type: string
 *                   description: The user's ID
 *                   example: "60c72b2f5f1b2c001c8e4a4b"
 *                 name:
 *                   type: string
 *                   description: The user's name
 *                   example: "Tom"
 *                 email:
 *                   type: string
 *                   description: The user's email
 *                   example: "tom@gmail.com"
 *                 accessToken:
 *                   type: string
 *                   description: JWT access token
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2MGM3MmIyZjVmMWIyYzAwMWM4ZTRhNGIiLCJzdWIiOiJhY2Nlc3NBcGkiLCJleHAiOjE2MzU3NTI0MDB9._1bCmxNxe5x6Pfxt5PjKzLwEtAYN9eI8mQUG"
 *       401:
 *         description: Unauthorized - Invalid email or password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Email is invalid" 
 *       422:
 *         description: Missing required fields
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Please fill in all fields (email and password)"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Some server error message"
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
      accessToken
    })
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
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                   description: The user's ID
 *                   example: "60c72b2f5f1b2c001c8e4a4b"
 *                 name:
 *                   type: string
 *                   description: The user's name
 *                   example: "Tom"
 *                 email:
 *                   type: string
 *                   description: The user's email
 *                   example: "tom@gmail.com"
 *       401:
 *         description: Unauthorized - Access token not found, invalid, or expired
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Access token not found" 
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Some server error message"
 */

router.get('/verify-login', verifyAuthentication, async (req, res) => {
  try {
    const user = await users.findOne({_id: req.user.id})
    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email
    })

  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
})

async function verifyAuthentication(req, res, next){
  const accessToken = req.headers.authorization?.split(' ')[1];
  if(!accessToken){
    return res.status(401).json({message: "Access token not found"});
  }
  try {
    const decodedAccessToken = jwt.verify(accessToken, accessTokenSecret);
    req.user = {id: decodedAccessToken.userId};
    next();
  } catch (error) {
    return res.status(401).json({message: 'Access token invalid or expired'});
  }
}


module.exports = router;
