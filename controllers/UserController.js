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
        return res.status(200).json({status: 200, message: "New user has been registered!.", data: {name, email, role}})
    } catch (error) {
        console.error("Error while registering user.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}