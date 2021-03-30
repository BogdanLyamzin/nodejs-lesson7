const express = require('express')
const bcrypt = require("bcryptjs")
const passport = require("passport");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const router = express.Router()

const {User} = require("../models");

const auth = (req, res, next)=> {
    passport.authenticate("jwt", {session: false}, (err, user)=> {
        if(!user || err) {
            return res.status(401).json({
                status: "error",
                code: 401,
                message: "You have no provileg"
            }))
        }
        req.user = user;
        next()
    })
}

router.post('/registration', async (req, res, next) => {
    const { login, email, password } = req.body
    const user = await User.findOne({ email })
    if (user) {
        return res.status(409).json({
            status: 'error',
            code: 409,
            message: 'Email is already in use',
            data: 'Conflict',
        })
    }
    try {
        // const cryptPassword = bcrypt.hashSync(password, bcrypt.genSaltSync(6));
        // const newUser = new User({ login, email, password: cryptPassword })
        const newUser = new User({ login, email})
        newUser.setPassword(password)
        const result = await newUser.save()
        res.status(201).json({
            status: 'success',
            code: 201,
            data: {
                user: result
            },
        })
    } catch (error) {
        next(error)
    }
})

router.post('/login', async (req, res, next) => {
    const { email, password } = req.body
    const user = await User.findOne({ email })

    if (!user || !user.validPassword(password)) {
        return res.status(400).json({
            status: 'error',
            code: 400,
            message: 'Incorrect login or password',
            data: 'Bad request',
        })
    }

    const payload = {
        id: user._id
    };
    const {SECRET_KEY} = process.env;

    const token = jwt.sign(payload, SECRET_KEY);

    res.json({
        status: 'success',
        code: 200,
        data: {
            token
        }
    })
})

router.post("/profile", auth, (req, res, next)=> {
  console.log(req.user)
})

module.exports = router
