const express = require("express");
const router = express.Router();
const prisma = require("../prismaClient");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { auth } = require("../middlewares/auth");
router.get("/users", async (req, res) => {
    const data = await prisma.user.findMany({
        include: { posts: true, comments: true },
        orderBy: { id: "desc" },
        take: 20,
    });
    res.json(data);
});
router.get("/users/:id", async (req, res) => {
    const { id } = req.params;
    const data = await prisma.user.findFirst({
        where: { id: Number(id) },
        include: { posts: true, comments: true },
    });
    res.json(data);
});
router.post("/users", async (req, res) => {
    const { name, username, bio, password } = req.body;

    // Check if all required fields are provided
    if (!name || !username || !password) {
        return res.status(400).json({ msg: "name, username, and password are required" });
    }

    try {
        // Check if the username already exists
        const existingUser = await prisma.user.findUnique({
            where: { username },
        });

        if (existingUser) {
            return res.status(409).json({ msg: "Username already exists" });
        }

        // Hash the password and create the new user
        const hash = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { name, username, password: hash, bio },
        });

        return res.status(201).json(user);

    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: "Server error" });
    }
});

router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res
            .status(400)
            .json({ msg: "username and password required" });
    }
    const user = await prisma.user.findUnique({
        where: { username },
    });
    if (user) {
        if (bcrypt.compare(password, user.password)) {
            const token = jwt.sign(user, process.env.JWT_SECRET);
            return res.json({ token, user });
        }
    }
    res.status(401).json({ msg: "incorrect username or password" });
});

router.get("/verify", auth, async (req, res) => {
    const user = res.locals.user;
    res.json(user);
   });
   
module.exports = { userRouter: router };
