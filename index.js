import express from 'express'
import dotnev from  'dotenv'
import cookieParser from 'cookie-parser'
import { connectDB } from './db/connectDB.js';
import authRoutes from './routes/auth.route.js'
import cors from "cors"

dotnev.config();
connectDB()
const app = express();

const PORT = process.env.PORT || 5000

app.use(express.json())
app.use(cookieParser())

// const corOptions ={
//     origin: process.env.CLIENT_URL || ['http://localhost:3000'],
//     credential: true,
//     methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE']
// }

const corOptions ={
    origin: process.env.CLIENT_URL || ['http://localhost:3000'],
        methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'] 
}

app.use(cors(corOptions))

//routes
app.use('/api/v1', authRoutes)

app.listen(PORT, ()=> console.log(`Server running on port ${PORT}`))