import { 
    ChangeEmailSuperAdmin,
    ChangeNameSuperAdmin,
    ChangePasswordSuperAdmin,
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
router.post("/super-admin/register", RegisterSuperAdmin)
router.post("/super-admin/login", LoginSuperAdmin)

// Put Method
router.put("/super-admin/change-name", verifySuperAdmin, ChangeNameSuperAdmin)
router.put("/super-admin/change-email", verifySuperAdmin, ChangeEmailSuperAdmin)
router.put("/super-admin/change-password", verifySuperAdmin, ChangePasswordSuperAdmin)

// Get method
router.get("/super-admin/get-all-user", verifySuperAdmin, GetAllUser)
router.get("/super-admin/get-user/:id", verifySuperAdmin, GetUserById)
router.get("/super-admin/get-all-admin", verifySuperAdmin, GetAllAdmin)
router.get("/super-admin/get-admin/:id", verifySuperAdmin, GetAdminById)

// delete method
router.delete("/super-admin/delete-all-user", verifySuperAdmin, DeleteAllUsers)
router.delete("/super-admin/delete-user/:id", verifySuperAdmin, DeleteUserById)
router.delete("/super-admin/delete-all-admin", verifySuperAdmin, DeleteAllAdmins)
router.delete("/super-admin/delete-admin/:id", verifySuperAdmin, DeleteAdminById)
router.delete("/super-admin/logout", LogoutSuperAdmin)

export default router