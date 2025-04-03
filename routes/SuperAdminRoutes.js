import { LoginSuperAdmin, LogoutSuperAdmin, RegisterAdmin, RegisterSuperAdmin } from "../controllers/SuperAdminControllers.js";
import express from "express";
import { verifyAdmin } from "../middleware/VerifySuperAdmin.js";

const router = express.Router()
router.post("/admin/register", verifyAdmin, RegisterAdmin)
router.post("/super-admin/register", RegisterSuperAdmin)
router.post("/super-admin/login", LoginSuperAdmin)
router.delete("/super-admin/logout", LogoutSuperAdmin)

export default router