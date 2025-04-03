import jsonwebtoken from "jsonwebtoken"
import User from "../models/UsersTable.js"
import Admin from "../models/AdminTable.js"
import argon2, { argon2id } from "argon2"
import SuperAdmin from "../models/SuperAdminTable.js"

// Register admin
export const RegisterAdmin = async(req, res) => {
    try {
        const {name, email, password} = req.body
        const role = "Admin"

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
            return res.status(400).json({status: 400, message: "The name or email already registered!.", data: {name, email}})
        } 
        
        // Hash the password to make it secure
        const hashedPassword = await argon2.hash(password, argon2id)

        // Create the user
        await Admin.create({
            name: name,
            email: email,
            role: role,
            password: hashedPassword
        })

        // Send the status to the client
        return res.status(200).json({status: 200, data: {name, email, role}, message:"New admin has been registered!."})
    } catch (error) {
        console.error("Error while registering user.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Register super admin
export const RegisterSuperAdmin = async(req, res) => {
    try {
        const {name, email, password} = req.body
        const role = "Super Admin"

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
            return res.status(400).json({status: 400, message: "The name or email already registered!.", data: {name, email}})
        } 
        
        // Hash the password to make it secure
        const hashedPassword = await argon2.hash(password, argon2id)

        // Create the user
        await SuperAdmin.create({
            name: name,
            email: email,
            role: role,
            password: hashedPassword
        })

        // Send the status to the client
        return res.status(200).json({status: 200, data: {name, email, role}, message:"New Super Admin has been registered!."})
    } catch (error) {
        console.error("Error while registering user.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Login super admin
export const LoginSuperAdmin = async(req, res) => {
    try {
        const {email, password} = req.body
        const jwt = jsonwebtoken

        // Check if the email is in the database
        const superAdmin = await SuperAdmin.findAll({where: {email: email}})
        if(!superAdmin[0]) {
            return res.status(404).json({status: 404, message: "The email is not registered yet."})
        } 

        const id = superAdmin[0].id
        const name = superAdmin[0].name
        const role = superAdmin[0].role
        const passwordSuperAdmin = superAdmin[0].password
        
        // Check if the password are the same
        const verifyPassword = await argon2.verify(passwordSuperAdmin, password)
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
        await SuperAdmin.update({authToken: authToken}, {
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
        return res.status(200).json({status: 200, message:`Successfully Logged in as ${role}!.`, data: {id, name, email, accessToken}})
    } catch (error) {
        console.error("Error while logging in.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}

// Logout super admin
export const LogoutSuperAdmin = async(req, res) => {

    // Check if the cookie is provided
    const cookie = req.cookies.authToken;
    if (!cookie) {
        return res.status(400).json({status: 400, message: "There is no cookie provided!."})
    }
    
    // Check if the data is in the database
    const superAdmin = await SuperAdmin.findAll({
        where: {authToken: cookie}
    })
    if (!superAdmin[0]) {
        return res.status(404).json({status: 404, message: "No data found."})
    }

    // Update the data using an ID
    const id = superAdmin[0].id
    await SuperAdmin.update({authToken: null}, {
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

// Get all admins API
export const GetAllAdmin = async(req, res) => {
    try {
        
        // Check if the table is there
        const admins = await Admin.findAll()
        if (!admins.length) {
            return res.status(400).json({status: 400, message: "No admins data found."})
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: "Success to retrieved all admins data!.",  data: admins})
    } catch (error) {
        console.error("Error while getting all the admin data.", error)
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


// Get admin by id API
export const GetAdminById = async(req, res) => {
    try {

        // Check if client provoded an id
        const {id} = req.params
        if (!id) {
            return res.status(400).json({status: 400, message: "No admin id provided."})
        }

        // Check if the table is there
        const adminById = await Admin.findAll({where: {id: id}})
        if (!adminById.length) {
            return res.status(400).json({status: 400, message: "No admin data found."})
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: `Success to retrieved the admin by id : ${id}.`, data: adminById})

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

// Delete all admins API
export const DeleteAllAdmins = async(req, res) => {
    try {
        
        // Check if the table is there
        const admins = await Admin.findAll()
        const deleteAllAdminData = await Admin.destroy({where: {}})
        if (!admins.length) {
            return res.status(400).json({status: 400, message: "No admins data found."})
        } else {
            deleteAllAdminData
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: "Success to deleted all the admins data!."})
    } catch (error) {
        console.error("Error while deleting all the admin data.", error)
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

// Delete admin by id API
export const DeleteAdminById = async(req, res) => {
    try {

        // Check if client provoded an id
        const {id} = req.params
        if (!id) {
            return res.status(400).json({status: 400, message: "No admin id provided."})
        }

        // Check if the table is there
        const adminId = await Admin.findAll({where: {id: id}})
        const deleteAdminById = await Admin.destroy({where: {id: id}})
        if (!adminId.length) {
            return res.status(400).json({status: 400, message: "No admin data found."})
        } else {
            deleteAdminById
        }

        // Send the data to the client
        return res.status(201).json({status: 201, message: `Success to deleted the admin by id : ${id}.`})

    } catch (error) {
        console.error("Error while deleting admin by id.", error)
        return res.status(500).json({message: "Internal server 500 error."})
    }
}