const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
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
      return res
        .status(422)
        .json({
          message: "Please fill in all fields (name, email and password)",
        });
    }

    if(await users.findOne({email: email})){
        return res.status(409).json({message: `User with email ${email} exists`})
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

module.exports = router;
