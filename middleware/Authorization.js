import jsonwebtoken from "jsonwebtoken"

export const verifySuperAdmin = (req, res, next) => {

    const jwt = jsonwebtoken
    // Check if there is a token
    const token = req.cookies.authToken
    if (!token) {
        return res.status(400).json({status: 400, message: "No token provided!."})
    }

    // Verify the token if the role is Admin
    jwt.verify(token, process.env.REFRESH_TOKEN, (err, decoded) => {
        if (err) {
            return res.status(401).json({status: 401, message: "Invalir or expired token!."})
        }
        const {role} = decoded
        if (role !== "Super Admin") {
            return res.status(401).json({status: 401, message: "You don't have permission to access this API!."})
        }
        next();
    })
}

export const verifyAdmin = (req, res, next) => {

    const jwt = jsonwebtoken
    // Check if there is a token
    const token = req.cookies.authToken
    if (!token) {
        return res.status(400).json({status: 400, message: "No token provided!."})
    }

    // Verify the token if the role is Admin
    jwt.verify(token, process.env.REFRESH_TOKEN, (err, decoded) => {
        if (err) {
            return res.status(401).json({status: 401, message: "Invalid or expired token!."})
        }
        const {role} = decoded
        if (role !== "Admin") {
            return res.status(401).json({status: 401, message: "You don't have permission to access this API!."})
        }
        next();
    })
}