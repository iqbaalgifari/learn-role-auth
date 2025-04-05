import jsonwebtoken from "jsonwebtoken"
import User from "../models/UsersTable.js"
import Admin from "../models/AdminTable.js"
import argon2 from "argon2"
import SuperAdmin from "../models/SuperAdminTable.js"

export const Login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const jwt = jsonwebtoken;

        // Try to find the user in each table
        const user = await User.findOne({ where: { email } });
        const admin = await Admin.findOne({ where: { email } });
        const superAdmin = await SuperAdmin.findOne({ where: { email } });

        let foundUser = null;
        let userType = "";

        if (user) {
            foundUser = user;
            userType = "User";
        } else if (admin) {
            foundUser = admin;
            userType = "Admin";
        } else if (superAdmin) {
            foundUser = superAdmin;
            userType = "Super Admin";
        } else {
            return res.status(404).json({ status: 404, message: "The email is not registered yet." });
        }

        const id = foundUser.id;
        const name = foundUser.name;
        const role = foundUser.role;
        const passwordUser = foundUser.password;

        const verifyPassword = await argon2.verify(passwordUser, password);
        if (!verifyPassword) {
            return res.status(400).json({ status: 400, message: "Invalid Credentials!" });
        }

        const accessToken = jwt.sign({ id, name, email, role }, process.env.ACCESS_TOKEN, {
            expiresIn: "20s"
        });

        const authToken = jwt.sign({ id, name, email, role }, process.env.REFRESH_TOKEN, {
            expiresIn: "1d"
        });

        // Update auth token based on user type
        if (userType === "User") {
            await User.update({ authToken }, { where: { id } });
        } else if (userType === "Admin") {
            await Admin.update({ authToken }, { where: { id } });
        } else if (userType === "Super Admin") {
            await SuperAdmin.update({ authToken }, { where: { id } });
        }

        res.cookie("authToken", authToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: "None",
            secure: true
        });

        return res.status(200).json({
            status: 200,
            message: `Successfully Logged in as ${role}!`,
            data: { name, email, role, accessToken }
        });

    } catch (error) {
        console.error("Error while logging in:", error);
        return res.status(500).json({ message: "Internal server 500 error." });
    }
};


export const Logout = async(req, res) => {

    // Check if the cookie is provided
    const cookie = req.cookies.authToken;
    if (!cookie) {
        return res.status(400).json({status: 400, message: "There is no cookie provided!."})
    }
    
    // Check if the data is in the database
    const user = await User.findOne({where: {authToken: cookie}})
    const admin = await Admin.findOne({where: {authToken: cookie}})
    const superAdmin = await SuperAdmin.findOne({where: {authToken: cookie}})

    let foundUser = null
    let userType = ""

    if (user) {
        foundUser = user
        userType = "User"
    } else if (admin) {
        foundUser = admin
        userType = "Admin"
    } else if (superAdmin) {
        foundUser = superAdmin
        userType = "Super Admin"
    } else {
        return res.status(404).json({status: 404, message: "No data found."})
    }

    const id = foundUser.id

    if (userType === "User") {
        await User.update({authToken: null}, {where: {id: id}})
    } else if (userType === "Admin") {
        await Admin.update({authToken: null}, {where: {id: id}})
    } else if (userType === "Super Admin") {
        await SuperAdmin.update({authToken: null}, {where: {id: id}})
    } 

    // Clear the cookie on the client side 
    res.clearCookie('authToken', {
        httpOnly: true,
        sameSite: 'None',
        secure: true, // Ensure it's only cleared if secure
    });

    // Return the status
    return res.status(200).json({message: "Successfully logged out!."})
}