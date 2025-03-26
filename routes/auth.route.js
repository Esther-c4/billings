import express from 'express'
import { checkAuth, forgotPassword, getAllUsers, login, register, resendVerificationCode, resetPassword, verifyEmail } from '../controllers/auth.Controller.js'
import { authorize, protect } from '../middlewares/authMiddleware.js'
import uploadMiddleware from '../utils/upload.js'

const router = express.Router()

router.post("/register", uploadMiddleware, register)
router.post("/verify-account", verifyEmail)
router.post("/resend-verification-code", resendVerificationCode)
router.post("/login", login)
router.get("/check-auth", protect, checkAuth)
router.get("/all-user", protect, authorize("super_admin"), getAllUsers)
router.post("/forgot-password", forgotPassword)
router.post("/reset-password/:token", resetPassword)



export default router