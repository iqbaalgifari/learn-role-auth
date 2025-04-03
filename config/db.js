import { Sequelize } from "sequelize";

const db = new Sequelize("learn_role_auth", "root", "", {
    dialect: "mysql"
})

export default db;