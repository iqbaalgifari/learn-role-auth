import { LoginUser, LogoutUser, RegisterUser } from "../controllers/UserControllers.js";
import express from "express";

const router = express.Router()
router.post("/user/register", RegisterUser)
router.post("/user/login", LoginUser)
router.delete("/user/logout", LogoutUser)

export default router