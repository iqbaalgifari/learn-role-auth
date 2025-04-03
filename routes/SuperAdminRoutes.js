import { 
    DeleteAdminById,
    DeleteAllAdmins,
    DeleteAllUsers,
    DeleteUserById,
    GetAdminById,
    GetAllAdmin, 
    GetAllUser, 
    GetUserById, 
    LoginSuperAdmin, 
    LogoutSuperAdmin, 
    RegisterAdmin, 
    RegisterSuperAdmin } from "../controllers/SuperAdminControllers.js";
import express from "express";
import { verifySuperAdmin } from "../middleware/Authorization.js";

const router = express.Router()

// Post method
router.post("/admin/register", verifySuperAdmin, RegisterAdmin)
router.post("/super-admin/register", verifySuperAdmin, RegisterSuperAdmin)
router.post("/super-admin/login", LoginSuperAdmin)

// Get method
router.get("/get-all-user", verifySuperAdmin, GetAllUser)
router.get("/get-user/:id", verifySuperAdmin, GetUserById)
router.get("/get-all-admin", verifySuperAdmin, GetAllAdmin)
router.get("/get-admin/:id", verifySuperAdmin, GetAdminById)

// Get method
router.delete("/delete-all-user", verifySuperAdmin, DeleteAllUsers)
router.delete("/delete-user/:id", verifySuperAdmin, DeleteUserById)
router.delete("/delete-all-admin", verifySuperAdmin, DeleteAllAdmins)
router.delete("/delete-admin/:id", verifySuperAdmin, DeleteAdminById)
router.delete("/super-admin/logout", LogoutSuperAdmin)

export default router