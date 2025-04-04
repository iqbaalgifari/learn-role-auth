import jsonwebtoken from "jsonwebtoken"
import User from "../models/UsersTable.js"
import Admin from "../models/AdminTable.js"
import argon2, { argon2id } from "argon2"
import SuperAdmin from "../models/SuperAdminTable.js"

const jwt = jsonwebtoken

// Login super admin
export const LoginAdmin = async(req, res) => {
    try {
        const {email, password} = req.body

        // Check if the email is in the database
        const admin = await Admin.findAll({where: {email: email}})
        if(!admin[0]) {
            return res.status(404).json({status: 404, message: "The email is not registered yet."})
        } 

        const id = admin[0].id
        const name = admin[0].name
        const role = admin[0].role
        const passwordAdmin = admin[0].password
        
        // Check if the password are the same
        const verifyPassword = await argon2.verify(passwordAdmin, password)
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
        await Admin.update({authToken: authToken}, {
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
        return res.status(200).json({status: 200, data: {name, email, role, accessToken}, message:`Successfully Logged in as ${role}!.`})
    } catch (error) {
        console.error("Error while logging in.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Logout super admin
export const LogoutAdmin = async(req, res) => {

    // Check if the cookie is provided
    const cookie = req.cookies.authToken;
    if (!cookie) {
        return res.status(400).json({status: 400, message: "There is no cookie provided!."})
    }
    
    // Check if the data is in the database
    const admin = await Admin.findAll({
        where: {authToken: cookie}
    })
    if (!admin[0]) {
        return res.status(404).json({status: 404, message: "No data found."})
    }

    // Update the data using an ID
    const id = admin[0].id
    await Admin.update({authToken: null}, {
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

// Change/update the admin name API
export const ChangeNameAdmin = async(req, res) => {
    try {
        
        // Req body
        const {oldName, newName} = req.body
        const cookie = req.cookies.authToken

        if (!cookie) {
            return res.status(404).json({status: 404, message: "No cookie provided!."})
        }

        // Verify the cookies
        jwt.verify(cookie, process.env.REFRESH_TOKEN, async (err, decoded) => {
            if (err) {
                return res.status(400).json({status: 400, message: "Invalid or expired token!."})
            }

            // Extract the id from the cookie
            const {id} = decoded
            console.log("ID : ", id);
            
            const admin = await Admin.findAll({where: {id: id}})
            if (!admin[0]) {
                return res.status(404).json({status: 404, message: "No data found!"})
            }

            // Check if the email is in database are matched
            const email = admin[0].email
            const name = admin[0].name
            
            if (!name) {
                return res.status(404).json({status: 404, message: "Name not registered yet!"})
            }
            if (oldName !== name) {
                return res.status(400).json({status: 400, message: "Name not matched!"})
            }

            // Check if the email is already existed in other table
            const [matchedNameInUserTable, matchedNameInAdminTable, matchedNameInSuperAdminTable] = await Promise.all([
                await User.findOne({where: {name: newName}}),
                await Admin.findOne({where: {name: newName}}),
                await SuperAdmin.findOne({where: {name: newName}}),
            ])
            if(matchedNameInUserTable || matchedNameInAdminTable || matchedNameInSuperAdminTable) {
                return res.status(400).json({status: 400, message: "The name already registered!, Choose another name.", data: {newName}})
            }

            // Update the super admin if the password matched
            await Admin.update({name: newName}, {where: {id: id}})
            return res.status(200).json({status: 200, message: "Sucess updating the name!.", data: {newName, email}})
        })
        
    } catch (error) {
        console.error("Error while updating the name.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Change/update the admin email API
export const ChangeEmailAdmin = async(req, res) => {
    try {
        
        // Req body
        const {oldEmail, newEmail} = req.body
        const cookie = req.cookies.authToken

        if (!cookie) {
            return res.status(404).json({status: 404, message: "No cookie provided!."})
        }

        // Verify the cookies
        jwt.verify(cookie, process.env.REFRESH_TOKEN, async (err, decoded) => {
            if (err) {
                return res.status(400).json({status: 400, message: "Invalid or expired token!."})
            }

            // Extract the id from the cookie
            const {id} = decoded
            console.log("ID : ", id);
            
            const admin = await Admin.findAll({where: {id: id}})
            if (!admin[0]) {
                return res.status(404).json({status: 404, message: "No data found!"})
            }

            // Check if the email is in database are matched
            const email = admin[0].email
            const name = admin[0].name
            
            if (!email) {
                return res.status(404).json({status: 404, message: "Email not registered yet!"})
            }
            if (oldEmail !== email) {
                return res.status(400).json({status: 400, message: "Email not matched!"})
            }

            // Check if the email is already existed in other table
            const [matchedEmailInUserTable, matchedEmailInAdminTable, matchedEmailInSuperAdminTable] = await Promise.all([
                await User.findOne({where: {email: newEmail}}),
                await Admin.findOne({where: {email: newEmail}}),
                await SuperAdmin.findOne({where: {email: newEmail}}),
            ])
            if(matchedEmailInUserTable || matchedEmailInAdminTable || matchedEmailInSuperAdminTable) {
                return res.status(400).json({status: 400, message: "The email already registered!, Choose another email.", data: {newEmail}})
            }

            // Update the super admin if the password matched
            await Admin.update({email: newEmail}, {where: {id: id}})
            return res.status(200).json({status: 200, message: "Sucess updating an email!.", data: {name, newEmail}})
        })
        
    } catch (error) {
        console.error("Error while updating the email.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Change/update the admin password API
export const ChangePasswordAdmin = async(req, res) => {
    try {
        
        // Req body
        const {oldPassword, newPassword} = req.body
        const cookie = req.cookies.authToken

        if (!cookie) {
            return res.status(400).json({status: 400, message: "No cookie provided!."})
        }

        // Verify the cookies
        jwt.verify(cookie, process.env.REFRESH_TOKEN, async (err, decoded) => {
            if (err) {
                return res.status(400).json({status: 400, message: "Invalid or expired token!."})
            }

            // Extract the id from the cookie
            const {id} = decoded
            const admin = await Admin.findAll({where: {id: id}})
            if (!admin) {
                return res.status(404).json({status: 404, message: "No data found!"})
            }

            // Check if old password and the password in database are matched
            const adminPassword = admin[0].password
            const name = admin[0].name
            const email = admin[0].email
            if (!adminPassword) {
                return res.status(404).json({status: 404, message: "No data found!"})
            }
            const isPasswordMatched = await argon2.verify(adminPassword, oldPassword)
            if (!isPasswordMatched) {
                return res.status(400).json({status: 400, message: "Password not matched!"})
            }

            // Hash the new password
            const hashedPassword = await argon2.hash(newPassword, argon2id)

            // Update the super admin if the password matched
            await Admin.update({password: hashedPassword}, {where: {id: id}})

            // Send the status to client
            return res.status(200).json({status: 200, message: "Sucess updating the password!.", data : {name, email}})
        })
        
    } catch (error) {
        console.error("Error while updating the password.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Get all users API
export const GetAllUser = async(req, res) => {
    try {
        
        // Check if the table is there
        const users = await User.findAll()
        if (!users.length) {
            return res.status(400).json({status: 400, message: "No users data found."})
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: "Success to retrieved all users data!.", data: users})
    } catch (error) {
        console.error("Error while getting all the user data.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Get user by id API
export const GetUserById = async(req, res) => {
    try {
        
        // Check if client provoded an id
        const {id} = req.params
        if (!id) {
            return res.status(400).json({status: 400, message: "No user id provided."})
        }

        // Check if the table is there
        const userById = await User.findAll({where: {id: id}})
        if (!userById.length) {
            return res.status(400).json({status: 400, message: "No user data found."})
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: `Success to retrieved the user by id : ${id}.`, data: userById})
        
    } catch (error) {
        console.error("Error while getting user by id.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Delete all users API
export const DeleteAllUsers = async(req, res) => {
    try {
        
        // Check if the table is there
        const users = await User.findAll()
        const deleteAllUserData = await User.destroy({where: {}})
        if (!users.length) {
            return res.status(400).json({status: 400, message: "No users data found."})
        } else {
            deleteAllUserData
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: "Success to deleted all the users data!."})

    } catch (error) {
        console.error("Error while deleting all the user data.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Delete user by id API
export const DeleteUserById = async(req, res) => {
    try {

        // Check if client provoded an id
        const {id} = req.params
        if (!id) {
            return res.status(400).json({status: 400, message: "No user id provided."})
        }

        // Check if the table is there
        const userId = await User.findAll({where: {id: id}})
        const deleteUserById = await User.destroy({where: {id: id}})
        if (!userId.length) {
            return res.status(400).json({status: 400, message: "No user data found."})
        } else {
            deleteUserById
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: `Success to deleted the user by id : ${id}.`})

    } catch (error) {
        console.error("Error while deleting user by id.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}