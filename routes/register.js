const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {
  accessTokenSecret,
  refreshTokenSecret,
  accessTokenExpiresIn,
  refreshTokenExpiresIn,
  cacheTemporaryTokenPrefix,
  cacheTemporaryTokenExpiresIn,
} = require("../config");
const { authenticator } = require("otplib");
const qrcode = require("qrcode");
const crypto = require("crypto");
const NodeCache = require("node-cache");

const router = express.Router();

const cache = new NodeCache();

const users = Datastore.create("Users.db");
const userRefreshTokens = Datastore.create("UserRefreshTokens.db");
const userInvalidTokens = Datastore.create("userInvalidTokens.db");

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
      "2faEnable": false,
      "2faSecret": null,
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

    if (user["2faEnable"]) {
      const tempToken = crypto.randomUUID();

      cache.set(
        cacheTemporaryTokenPrefix + tempToken,
        user._id,
        cacheTemporaryTokenExpiresIn
      );

      return res
        .status(200)
        .json({ tempToken, expiresInSeconds: cacheTemporaryTokenExpiresIn });
    } else {
      const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, {
        subject: "accessApi",
        expiresIn: accessTokenExpiresIn,
      });

      const refreshToken = jwt.sign({ userId: user._id }, refreshTokenSecret, {
        subject: "refreshToken",
        expiresIn: refreshTokenExpiresIn,
      });

      await userRefreshTokens.insert({
        refreshToken,
        userId: user._id,
      });

      return res.status(200).json({
        message: "User logged in successfully",
        id: user._id,
        name: user.name,
        email: user.email,
        accessToken,
        refreshToken,
      });
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /login/2fa:
 *   post:
 *     summary: Verify 2FA code for login
 *     description: Complete login by verifying the Time-based One-Time Password (TOTP) using the temporary token from the login request.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               tempToken:
 *                 type: string
 *                 description: The temporary token provided after entering email and password
 *               totp:
 *                 type: string
 *                 description: The Time-based One-Time Password (TOTP) generated by the authenticator app
 *           example:
 *             tempToken: "temporary-token-here"
 *             totp: "123456"
 *     responses:
 *       200:
 *         description: 2FA verification successful, user logged in
 *       401:
 *         description: Unauthorized - Temporary token or TOTP is invalid or expired
 *       422:
 *         description: Missing required fields
 *       500:
 *         description: Internal server error
 */

router.post("/login/2fa", async(req, res)=>{
      try {
        const{tempToken, totp} = req.body

        if(!tempToken || !totp){
            return res.status(422).json({message: 'Please fill in all fields (tempToken and totp)'})
        }
        const userId = cache.get(cacheTemporaryTokenPrefix + tempToken)

        if (!userId) {
          return res.status(401).json({message: 'The provided temporary token is incorrect or expired'})
        }

        const user = await users.findOne({_id: userId})

        const verified = authenticator.check(totp, user['2faSecret'])

        if (!verified) {
          return res.status(401).json({message: 'The provided TOTP is incorrect or expired'})
        }

        const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, {
        subject: "accessApi",
        expiresIn: accessTokenExpiresIn,
      });

      const refreshToken = jwt.sign({ userId: user._id }, refreshTokenSecret, {
        subject: "refreshToken",
        expiresIn: refreshTokenExpiresIn,
      });

      await userRefreshTokens.insert({
        refreshToken,
        userId: user._id,
      });

      return res.status(200).json({
        message: "User logged in successfully",
        id: user._id,
        name: user.name,
        email: user.email,
        accessToken,
        refreshToken,
      });
      } catch (error) {
        return res.status(500).json({ message: error.message });
      }
})

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
 * /refresh-token:
 *   post:
 *     summary: Refresh the access token using a refresh token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: The user's refresh token
 *           example:
 *             refreshToken: "your-refresh-token-here"
 *     responses:
 *       200:
 *         description: Access token refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                   description: The new access token
 *                 refreshToken:
 *                   type: string
 *                   description: The new refresh token
 *               example:
 *                 accessToken: "new-access-token-here"
 *                 refreshToken: "new-refresh-token-here"
 *       401:
 *         description: Unauthorized - Refresh token not found, invalid, or expired
 *       500:
 *         description: Internal server error
 */

router.post("/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not found" });
    }

    const decodedRefreshToken = jwt.verify(refreshToken, refreshTokenSecret);

    const userRefreshToken = await userRefreshTokens.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    });

    if (!userRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired" });
    }

    await userRefreshTokens.remove({ _id: userRefreshTokens._id });
    await userRefreshTokens.compactDatafile();

    const accessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      accessTokenSecret,
      {
        subject: "accessApi",
        expiresIn: accessTokenExpiresIn,
      }
    );

    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      refreshTokenSecret,
      {
        subject: "refreshToken",
        expiresIn: refreshTokenExpiresIn,
      }
    );

    await userRefreshTokens.insert({
      refreshToken: newRefreshToken,
      userId: decodedRefreshToken.userId,
    });

    return res.status(200).json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    if (
      error instanceof jwt.TokenExpiredError ||
      error instanceof jwt.JsonWebTokenError
    ) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired" });
    }
  }
});

/**
 * @swagger
 * /2fa/generate:
 *   get:
 *     summary: Generate a QR code for enabling two-factor authentication
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Two-factor authentication secret and QR code generated successfully
 *         content:
 *           image/png:
 *             schema:
 *               type: string
 *               format: binary
 *               description: A QR code image in PNG format
 *       401:
 *         description: Unauthorized - Access token not found or invalid
 *       500:
 *         description: Internal server error
 */

router.get("/2fa/generate", verifyAuthentication, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });

    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(user.email, "tomking.io", secret);

    await users.update({ _id: req.user.id }, { $set: { "2faSecret": secret } });
    await users.compactDatafile();

    const qrCode = await qrcode.toBuffer(uri, { type: "image/png", margin: 1 });

    res.setHeader("Content-Disposition", "attachment; filename=qrcode.png");
    return res.status(200).type("image/png").send(qrCode);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /2fa/validate:
 *   post:
 *     summary: Validate the user's TOTP to enable two-factor authentication
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               totp:
 *                 type: string
 *                 description: The Time-based One-Time Password (TOTP) from the authenticator app
 *             example:
 *               totp: "123456"
 *     responses:
 *       200:
 *         description: TOTP validated successfully
 *       400:
 *         description: Bad Request - TOTP is incorrect or expired
 *       422:
 *         description: Unprocessable Entity - TOTP is required
 *       401:
 *         description: Unauthorized - Access token not found or invalid
 *       500:
 *         description: Internal Server Error
 */

router.post("/2fa/validate", verifyAuthentication, async (req, res) => {
  try {
    const { totp } = req.body;

    if (!totp) {
      return res.status(422).json({ message: "TOTP is required" });
    }

    const user = await users.findOne({ _id: req.user.id });

    const verified = authenticator.check(totp, user["2faSecret"]);

    if (!verified) {
      return res
        .status(400)
        .json({ message: "TOTP is not correct or expired" });
    }

    await users.update({ _id: req.user.id }, { $set: { "2faEnable": true } });
    await users.compactDatafile();

    return res.status(200).json({ message: "TOTP validated successfully" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /logout:
 *   get:
 *     summary: Log out the user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       204:
 *         description: User logged out successfully
 *       401:
 *         description: Unauthorized - Access token not found or invalid
 *       500:
 *         description: Internal server error
 */

router.post("/logout", verifyAuthentication, async (req, res) => {
  try {
    await userRefreshTokens.removeMany({ userId: req.user.id });
    await userRefreshTokens.compactDatafile();

    await userInvalidTokens.insert({
      accessToken: req.accessToken.value,
      userId: req.user.id,
      expirationTime: req.accessToken.exp,
    });

    return res.status(204).send();
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
  if (await userInvalidTokens.findOne({ accessToken })) {
    return res
      .status(401)
      .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
  }
  try {
    const decodedAccessToken = jwt.verify(accessToken, accessTokenSecret);
    req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
    req.user = { id: decodedAccessToken.userId };
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ message: "Access token expired", code: "AccessTokenExpired" });
    } else if (error instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
    } else {
      return res.status(500).json({ message: error.message });
    }
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
