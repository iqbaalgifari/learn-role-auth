import express from "express";
import { RegisterUser } from "../controllers/UserController.js";

const router = express.Router()
router.post("/user/register", RegisterUser)

export default router