import { DataTypes } from "sequelize";
import db from "../config/db.js";

const Admin = db.define("admins", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        unique: true
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    role: {
        type: DataTypes.STRING,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    authToken: {
        type: DataTypes.STRING(400),
        allowNull: true
    }
}, {
    freezeTableName: true
})

export default Admin