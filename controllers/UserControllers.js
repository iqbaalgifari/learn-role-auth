import jsonwebtoken from "jsonwebtoken"
import User from "../models/UsersTable.js"
import Admin from "../models/AdminTable.js"
import argon2, { argon2id } from "argon2"
import SuperAdmin from "../models/SuperAdminTable.js"

export const RegisterUser = async(req, res) => {
    try {
        const {name, email, password} = req.body
        const role = "User"

        // Check if name and email is already exister in other table
        const [matchedNameInUserTable, matchedEmailInUserTable, matchedNameInAdminTable, matchedEmailInAdminTable, matchedNameInSuperAdminTable, matchedEmailInSuperAdminTable] = await Promise.all([
            await User.findOne({where: {name: name}}),
            await User.findOne({where: {email: email}}),
            await Admin.findOne({where: {name: name}}),
            await Admin.findOne({where: {email: email}}),
            await SuperAdmin.findOne({where: {name: name}}),
            await SuperAdmin.findOne({where: {email: email}}),
        ])
        if(matchedNameInUserTable || matchedEmailInUserTable || matchedNameInAdminTable || matchedEmailInAdminTable || matchedNameInSuperAdminTable || matchedEmailInSuperAdminTable) {
            return res.status(400).json({status: 400, message: "The name or email already registered!."})
        } 
        
        // Hash the password to make it secure
        const hashedPassword = await argon2.hash(password, argon2id)

        // Create the user
        await User.create({
            name: name,
            email: email,
            role: role,
            password: hashedPassword
        })

        // Send the status to the client
        return res.status(200).json({status: 200, data: {name, email, role}, message:"New user has been registered!."})
    } catch (error) {
        console.error("Error while registering user.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

export const LoginUser = async(req, res) => {
    try {
        const {email, password} = req.body
        const jwt = jsonwebtoken

        // Check if the email is in the database
        const user = await User.findAll({where: {email: email}})
        if(!user[0]) {
            return res.status(404).json({status: 404, message: "The email is not registered yet."})
        } 

        const id = user[0].id
        const name = user[0].name
        const role = user[0].role
        const passwordUser = user[0].password
        
        // Check if the password are the same
        const verifyPassword = await argon2.verify(passwordUser, password)
        if (!verifyPassword) {
            return res.status(400).json({status: 400, message: "Invalid Credentials!."})
        }

        // Create access token and auth token
        const accessToken = jwt.sign({id, name, email, role}, process.env.ACCESS_TOKEN, {
            expiresIn: "20s"
        })
        const authToken = jwt.sign({id, name, email, role}, process.env.REFRESH_TOKEN, {
            expiresIn: "1d"
        })

        // Update the authToken in the database
        await User.update({authToken: authToken}, {
            where: {id: id}
        })

        // Send the cookie to client
        res.cookie("authToken", authToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite : "None",
            secure : true
        })

        // Send the status to client
        return res.status(200).json({status: 200, data: {id, name, email, accessToken}, message:`Successfully Logged in as ${role}!.`})
    } catch (error) {
        console.error("Error while logging in.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

export const LogoutUser = async(req, res) => {

    // Check if the cookie is provided
    const cookie = req.cookies.authToken;
    if (!cookie) {
        return res.status(400).json({status: 400, message: "There is no cookie provided!."})
    }
    
    // Check if the data is in the database
    const user = await User.findAll({
        where: {authToken: cookie}
    })
    if (!user[0]) {
        return res.status(404).json({status: 404, message: "No data found."})
    }

    // Update the data using an ID
    const id = user[0].id
    await User.update({authToken: null}, {
        where: {id: id}
    })

    // Clear the cookie on the client side 
    res.clearCookie('authToken', {
        httpOnly: true,
        sameSite: 'None',
        secure: true, // Ensure it's only cleared if secure
    });

    // Return the status
    return res.status(200).json({message: "Successfully logged out!."})
}