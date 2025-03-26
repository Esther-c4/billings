import {sendVerificationEmail, sendWelcomeEmail,sendPasswordResetEmail,sendResetSuccessEmail } from "../mailtrap/emails.js";
import User from "../models/userModel.js"
import jwt from 'jsonwebtoken'
import crypto from "crypto"

//to create user
export const register = async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body

        // to handle image
        const avatar = req.files?.avatar?.[0]?.path || null;

        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" })
        }

        const verificationToken = Math.floor(100000 + Math.random() * 900000).toString()

        let user = new User({
            firstName,
            lastName,
            email,
            password,
            avatar: avatar,
            role: "user",
            verificationToken,
            verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000  //expires after 24hrs
        })
        await user.save()
        await sendVerificationEmail(user.email, verificationToken)


        // formular to request for token
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECERT, { expiresIn: "2d" })

        res.status(201).json({ success: true, message: "User created successfully", user, token })
    } catch (error) {
        res.status(500).json({ success: false, message: error.message })
    }
}

//to verify user email
export const verifyEmail = async (req, res) => {
    const { code } = req.body;

    try {
        const user = await User.findOne({ verificationTokenExpiresAt: code, verificationTokenExpiresAt: { $gt: Date.now() } })
        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired verification code" })
        }
        user.isVerified = true,
            user.verificationToken = undefined,
            user.verificationTokenExpiresAt = undefined
        await user.save()

        await sendWelcomeEmail(user.email)

        res.status(200).json({
            success: true,
            message: "Email verified successfully.",
            user: {
                ...user._doc,
                password: undefined
            }
        })
    } catch (error) {
        console.log("error in verifyEmail", error)
        res.status(500).json({ success: false, message: error.message })
    }
}

//function to reset password
export const resendVerificationCode = async (req, res) => {
    const { email } = req.body
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ success: false, message: "User not found" })
        }

        if (user.isVerified) {
            return res.status(400).json({ success: false, message: "User is already verified" })
        }

        const verificationToken = Math.floor(100000 + Math.random() * 900000).toString()
        verificationTokenExpiresAt = Date.now() + 10 * 60 * 1000  //expires after 10 mins

        user.verificationToken = verificationToken
        user.verificationTokenExpiresAt = verificationTokenExpiresAt

        await user.save()
        await sendVerificationEmail(user.email, user.firstName, verificationToken)

        return res.status(200).json({ success: true, message: "Verification code sent successfully", verificationToken, verificationTokenExpiresAt })
    } catch (error) {
        console.log("error in verifyEmail", error)
        res.status(500).json({ success: false, message: error.message })
    }
}

//function for forgot password
export const forgotPassword = async (req, res) => {
    const { email } = req.body
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ success: true, message: "If an account exists with this email, a password reset link will be sent shortly." })
        }

        // generate password reset token
        const resetToken = crypto.randomBytes(20).toString("hex")
        const resetPasswordExpireAt = Date.now() + 2 * 60 * 1000

        user.resetPasswordToken = resetToken
        user.resetPasswordExpireAt = resetPasswordExpireAt

        await user.save()
        await sendPasswordResetEmail(user.email, `${process.env.CLIENT_URL}/reset-password/${resetToken}`) // function to take u to a different site wia u can reset password
        return res.status(400).json({ success: true, message: "If an account exists with this email, a password reset link will be sent shortly." })
    } catch (error) {
        console.log("error in verifyEmail", error)
        res.status(500).json({ success: false, message: error.message })
    }
}

//function to reset passowrd
export const resetPassword = async (req, res) => {
    try {
        const { token } = req.params
        const { password } = req.body
        const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpireAt: { $gt: Date.now() } })

        if (!user || !(await user.comparePassword(password))) {
            return res.status(403).json({ success: false, message: "Invalid credentials." })
        }

        user.password = password
        user.resetPasswordToken = undefined
        user.resetPasswordExpireAt = undefined
        await user.save()

        await sendResetSuccessEmail(user.email)
        res.status(200).json({ success: true, message: "password reset successfully" })
    } catch (error) {
        res.status(500).json({ success: false, message: error.message })
    }
}

//to login user
export const login = async (req, res) => {
    try {
        const { email, password } = req.body
        const user = await User.findOne({ email })
        if (!user || !(await user.comparePassword(password))) {
            return res.status(403).json({ success: false, message: "Invalid credentials." })
        }

        if (!user.isVerified) {
            return res.status(403).json({ success: false, message: "Please verify your email to login" })
        }
        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECERT,
            { expiresIn: "2d" }
        )
        user.lastLogin = new Date()
        user.isOnline = true
        await user.save()

        res.status(200).json({ success: true, message: "User logged in successfully", user, token })
    } catch (error) {
        res.status(500).json({ success: false, message: error.message })
    }
}

//to getAllUsers
export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find().populate("firstName")
        res.status(200).json({ success: true, message: "Users retrieved successfully.", users })
    } catch (error) {
        res.status(500).json({ success: false, message: error.message })
    }
}

export const checkAuth = async(req, res)=>{
    try {
       const user = await User.findById(req.user).select("-password")
       if(!user){
        return res.status(400).json({ success: false, message: "User not found" })
       }
       res.status(200).json({success: true, user})
    } catch (error) {
        console.log("Error in checkAuth", error)
        res.status(500).json({ success: false, message: error.message }) 
    }
}