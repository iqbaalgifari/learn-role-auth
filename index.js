import express from "express";
import db from "./config/db.js";
import Admin from "./models/AdminTable.js";
import SuperAdmin from "./models/SuperAdminTable.js";
import User from "./models/UsersTable.js";
import { configDotenv } from "dotenv";
import cookieParser from "cookie-parser";
import UserRoutes from "./routes/UserRoutes.js";
import SuperAdminRoutes from "./routes/SuperAdminRoutes.js";
import AdminRoutes from "./routes/AdminRoutes.js";
import AuthRoutes from "./routes/AuthRoutes.js";

const app = express()
const PORT = 8000

if (db.authenticate() && Admin.sync() && SuperAdmin.sync() && User.sync() && configDotenv()) {
    console.log(
    "Connected to the database.\n",
    "Syncing Admins table.\n",
    "Syncing Super Admin table.\n",
    "Syncing Users table.\n",
    "Successfully configured env."
    );
} else {
    console.log("Error while connecting to the database.");
}
app.use(express.json())
app.use(cookieParser())
app.use(AdminRoutes)
app.use(AuthRoutes)
app.use(SuperAdminRoutes)
app.use(UserRoutes)
app.listen(PORT, () => {console.log(`Your server is running on http://localhost:${PORT}`)})
app.get("/", async(req, res) => {
    res.send("Welcome to topic learning role-based auth!")
})

