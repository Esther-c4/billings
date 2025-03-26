import jwt from 'jsonwebtoken'
import User from '../models/userModel.js'

// to
export const protect = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1]
        if (!token) return res.status(401).json({ message: "Not authorized." })
        const decoded = jwt.verify(token, process.env.JWT_SECERT)
        req.user = await User.findById(decoded.id)
        next()
    } catch (error) {
        res.status(401).json({ message: "Invalid token." })
    }
}

// rbac meaning role base access control to give role to user
export const authorize =(...roles)=>{
    return (req,res,next)=>{
        if(!roles.includes(req.user.role)){
            return res.status(403).json({message: "Access denied"})
        }
        next()
    }
}