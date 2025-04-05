import { 
    ChangeEmailAdmin,
    ChangeNameAdmin,
    ChangePasswordAdmin,
    DeleteAllUsers,
    DeleteUserById,
    GetAllUser, 
    GetUserById, 
} from "../controllers/AdminControllers.js";
import { verifyAdmin } from "../middleware/Authorization.js";
import express from "express";

const router = express.Router()

// Put method
router.put("/admin/change-name", verifyAdmin, ChangeNameAdmin)
router.put("/admin/change-email", verifyAdmin, ChangeEmailAdmin)
router.put("/admin/change-passwod", verifyAdmin, ChangePasswordAdmin)

// Get Method
router.get("/admin/get-all-user", verifyAdmin, GetAllUser)
router.get("/admin/get-user/:id", verifyAdmin, GetUserById)

// Delete Method
router.delete("/admin/delete-all-user", verifyAdmin, DeleteAllUsers)
router.delete("/admin/delete-user/:id", verifyAdmin, DeleteUserById)

export default router