import mongoose from 'mongoose'

export const connectDB = async()=>{
    try {
       const conn = await mongoose.connect(process.env.CONNECT_STRING)
       console.log(`MongoDB Connected: ${conn.connection.host}`) 
    } catch (error) {
        console.log('Error connecting to mongoDB:', error.message)
        process.exit(1)
    }
}