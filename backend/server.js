// ========================================
// AGRI LINKK - BACKEND SERVER
// ========================================

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// ========================================
// MIDDLEWARE
// ========================================

app.use(cors());
app.use(express.json());

// ========================================
// ENVIRONMENT VARIABLES
// ========================================

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("ERROR: JWT_SECRET is not configured.");
    process.exit(1);
}

if (
    !process.env.DB_HOST ||
    !process.env.DB_USER ||
    !process.env.DB_PASSWORD ||
    !process.env.DB_NAME
) {
    console.error("ERROR: MySQL environment variables are missing.");
    process.exit(1);
}

// ========================================
// MYSQL CONNECTION POOL - AIVEN
// ========================================

const db = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 10349),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,

    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    connectTimeout: 60000,

    enableKeepAlive: true,
    keepAliveInitialDelay: 0,

    ssl: {
        rejectUnauthorized: false
    }
});

const promiseDb = db.promise();

// ========================================
// DATABASE CONNECTION TEST
// ========================================

async function testDatabaseConnection() {
    try {
        const connection = await promiseDb.getConnection();

        try {
            await connection.query("SELECT 1 AS test");
            console.log("MySQL connected successfully!");
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error(
            "MySQL connection failed:",
            error.code || error.message
        );
    }
}

// ========================================
// HOME ROUTE
// ========================================

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "AGRI LINKK API is running successfully!"
    });
});

// ========================================
// DATABASE TEST ROUTE
// ========================================

app.get("/test-db", async (req, res) => {
    try {
        const [results] = await promiseDb.query(
            "SELECT 1 AS test"
        );

        res.json({
            success: true,
            message: "Database connected successfully!",
            result: results
        });
    } catch (error) {
        console.error(
            "Database test error:",
            error.code || error.message
        );

        res.status(500).json({
            success: false,
            message: "Database connection failed",
            error: error.code || "DATABASE_ERROR"
        });
    }
});

// ========================================
// AUTHENTICATE TOKEN
// ========================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    const token =
        authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Access token required"
        });
    }

    jwt.verify(token, JWT_SECRET, (error, user) => {
        if (error) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token"
            });
        }

        req.user = user;
        next();
    });
}

// ========================================
// AUTHENTICATE ADMIN
// ========================================

function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, () => {
        if (req.user.role !== "Admin") {
            return res.status(403).json({
                success: false,
                message: "Admin access required"
            });
        }

        next();
    });
}

// ========================================
// REGISTER
// ========================================

app.post("/api/register", async (req, res) => {
    try {
        const {
            full_name,
            email,
            phone,
            role,
            password
        } = req.body;

        if (
            !full_name ||
            !email ||
            !phone ||
            !role ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        const validRoles = [
            "Farmer",
            "MSME",
            "Logistics",
            "Community",
            "Apartment",
            "Admin"
        ];

        if (!validRoles.includes(role)) {
            return res.status(400).json({
                success: false,
                message: "Invalid role"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const [existingUsers] = await promiseDb.execute(
            "SELECT id FROM users WHERE email = ?",
            [normalizedEmail]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Email already registered"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await promiseDb.execute(
            `INSERT INTO users
            (full_name, email, phone, role, password)
            VALUES (?, ?, ?, ?, ?)`,
            [
                full_name.trim(),
                normalizedEmail,
                phone.trim(),
                role,
                hashedPassword
            ]
        );

        res.status(201).json({
            success: true,
            message: "Registration successful",
            userId: result.insertId
        });
    } catch (error) {
        console.error(
            "Registration error:",
            error.code || error.message
        );

        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                success: false,
                message: "Email already registered"
            });
        }

        res.status(500).json({
            success: false,
            message: "Registration failed"
        });
    }
});

// ========================================
// LOGIN
// ========================================

app.post("/api/login", async (req, res) => {
    try {
        const { email, password, role } = req.body;

        if (!email || !password || !role) {
            return res.status(400).json({
                success: false,
                message: "Email, password and role are required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const [users] = await promiseDb.execute(
            `SELECT
                id,
                full_name,
                email,
                phone,
                role,
                password,
                created_at
             FROM users
             WHERE email = ? AND role = ?`,
            [normalizedEmail, role]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid email, password or role"
            });
        }

        const user = users[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid email, password or role"
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                role: user.role
            },
            JWT_SECRET,
            {
                expiresIn: "24h"
            }
        );

        delete user.password;

        res.json({
            success: true,
            message: "Login successful",
            token,
            user
        });
    } catch (error) {
        console.error(
            "Login error:",
            error.code || error.message
        );

        res.status(500).json({
            success: false,
            message: "Login failed"
        });
    }
});

// ========================================
// FARMER - SAVE FARM DETAILS
// ========================================

app.post(
    "/api/farm-details",
    authenticateToken,
    async (req, res) => {
        try {
            if (req.user.role !== "Farmer") {
                return res.status(403).json({
                    success: false,
                    message: "Farmer access required"
                });
            }

            const {
                land_area,
                land_location,
                crop_name,
                farming_type
            } = req.body;

            if (
                land_area == null ||
                !land_location ||
                !crop_name ||
                !farming_type
            ) {
                return res.status(400).json({
                    success: false,
                    message: "All farm details are required"
                });
            }

            const [farmers] = await promiseDb.execute(
                "SELECT id FROM farmers WHERE user_id = ?",
                [req.user.id]
            );

            if (farmers.length > 0) {
                await promiseDb.execute(
                    `UPDATE farmers
                     SET land_area = ?,
                         land_location = ?,
                         crop_name = ?,
                         farming_type = ?
                     WHERE user_id = ?`,
                    [
                        land_area,
                        land_location,
                        crop_name,
                        farming_type,
                        req.user.id
                    ]
                );

                return res.json({
                    success: true,
                    message: "Farm details updated successfully"
                });
            }

            await promiseDb.execute(
                `INSERT INTO farmers
                (
                    user_id,
                    land_area,
                    land_location,
                    crop_name,
                    farming_type
                )
                VALUES (?, ?, ?, ?, ?)`,
                [
                    req.user.id,
                    land_area,
                    land_location,
                    crop_name,
                    farming_type
                ]
            );

            res.status(201).json({
                success: true,
                message: "Farm details saved successfully"
            });
        } catch (error) {
            console.error(
                "Save farm details error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// FARMER - GET FARM DETAILS
// ========================================

app.get(
    "/api/farm-details",
    authenticateToken,
    async (req, res) => {
        try {
            if (req.user.role !== "Farmer") {
                return res.status(403).json({
                    success: false,
                    message: "Farmer access required"
                });
            }

            const [results] = await promiseDb.execute(
                "SELECT * FROM farmers WHERE user_id = ?",
                [req.user.id]
            );

            res.json({
                success: true,
                farm: results.length > 0 ? results[0] : null
            });
        } catch (error) {
            console.error(
                "Get farm details error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// FARMER - ADD PRODUCT
// ========================================

app.post(
    "/api/products",
    authenticateToken,
    async (req, res) => {
        try {
            if (req.user.role !== "Farmer") {
                return res.status(403).json({
                    success: false,
                    message: "Farmer access required"
                });
            }

            const {
                product_name,
                quantity,
                grade,
                price,
                description
            } = req.body;

            if (
                !product_name ||
                quantity == null ||
                quantity === "" ||
                !grade ||
                price == null ||
                price === ""
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Product name, quantity, grade and price are required"
                });
            }

            const numericQuantity = Number(quantity);
            const numericPrice = Number(price);

            if (
                !Number.isFinite(numericQuantity) ||
                numericQuantity <= 0 ||
                !Number.isFinite(numericPrice) ||
                numericPrice < 0
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Quantity must be positive and price must be non-negative"
                });
            }

            const [farmers] = await promiseDb.execute(
                "SELECT id FROM farmers WHERE user_id = ?",
                [req.user.id]
            );

            if (farmers.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "Please save your farm details first"
                });
            }

            const [result] = await promiseDb.execute(
                `INSERT INTO products
                (
                    farmer_id,
                    product_name,
                    quantity,
                    grade,
                    price,
                    description
                )
                VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    farmers[0].id,
                    product_name,
                    numericQuantity,
                    grade,
                    numericPrice,
                    description || ""
                ]
            );

            res.status(201).json({
                success: true,
                message: "Product added successfully",
                productId: result.insertId
            });
        } catch (error) {
            console.error(
                "Add product error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// FARMER - GET OWN PRODUCTS
// ========================================

app.get(
    "/api/products",
    authenticateToken,
    async (req, res) => {
        try {
            if (req.user.role !== "Farmer") {
                return res.status(403).json({
                    success: false,
                    message: "Farmer access required"
                });
            }

            const [products] = await promiseDb.execute(
                `SELECT
                    p.*,
                    f.crop_name,
                    f.farming_type
                 FROM products p
                 JOIN farmers f ON p.farmer_id = f.id
                 WHERE f.user_id = ?
                 ORDER BY p.created_at DESC`,
                [req.user.id]
            );

            res.json({
                success: true,
                products
            });
        } catch (error) {
            console.error(
                "Get products error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// MARKET PRODUCTS
// ========================================

app.get(
    "/api/market-products",
    authenticateToken,
    async (req, res) => {
        try {
            const [products] = await promiseDb.query(
                `SELECT
                    p.id,
                    p.product_name,
                    p.quantity,
                    p.grade,
                    p.price,
                    p.description,
                    p.created_at,
                    u.full_name AS farmer_name,
                    u.phone AS farmer_phone,
                    f.crop_name,
                    f.farming_type,
                    f.land_location
                 FROM products p
                 JOIN farmers f ON p.farmer_id = f.id
                 JOIN users u ON f.user_id = u.id
                 ORDER BY p.created_at DESC`
            );

            res.json({
                success: true,
                products
            });
        } catch (error) {
            console.error(
                "Market products error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// DELETE PRODUCT
// ========================================

app.delete(
    "/api/products/:productId",
    authenticateToken,
    async (req, res) => {
        try {
            if (req.user.role !== "Farmer") {
                return res.status(403).json({
                    success: false,
                    message: "Farmer access required"
                });
            }

            const productId = Number(req.params.productId);

            if (!Number.isInteger(productId) || productId <= 0) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid product ID"
                });
            }

            const [result] = await promiseDb.execute(
                `DELETE p
                 FROM products p
                 JOIN farmers f ON p.farmer_id = f.id
                 WHERE p.id = ? AND f.user_id = ?`,
                [productId, req.user.id]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Product not found"
                });
            }

            res.json({
                success: true,
                message: "Product deleted successfully"
            });
        } catch (error) {
            console.error(
                "Delete product error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// ADMIN - GET ALL USERS
// ========================================

app.get(
    "/api/admin/users",
    authenticateAdmin,
    async (req, res) => {
        try {
            const [users] = await promiseDb.query(
                `SELECT
                    id,
                    full_name,
                    email,
                    phone,
                    role,
                    created_at
                 FROM users
                 ORDER BY created_at DESC`
            );

            res.json({
                success: true,
                users
            });
        } catch (error) {
            console.error(
                "Admin users error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// ADMIN - GET ALL PRODUCTS
// ========================================

app.get(
    "/api/admin/products",
    authenticateAdmin,
    async (req, res) => {
        try {
            const [products] = await promiseDb.query(
                `SELECT
                    p.id,
                    p.product_name,
                    p.quantity,
                    p.grade,
                    p.price,
                    p.description,
                    p.created_at,
                    u.full_name AS farmer_name,
                    f.crop_name,
                    f.farming_type
                 FROM products p
                 JOIN farmers f ON p.farmer_id = f.id
                 JOIN users u ON f.user_id = u.id
                 ORDER BY p.created_at DESC`
            );

            res.json({
                success: true,
                products
            });
        } catch (error) {
            console.error(
                "Admin products error:",
                error.code || error.message
            );

            res.status(500).json({
                success: false,
                message: "Database error"
            });
        }
    }
);

// ========================================
// GLOBAL ERROR HANDLER
// ========================================

app.use((error, req, res, next) => {
    console.error(
        "Unhandled server error:",
        error.message || error
    );

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        success: false,
        message: "Internal server error"
    });
});

// ========================================
// SERVER
// ========================================

app.listen(PORT, "0.0.0.0", () => {
    console.log(`AGRI LINKK server running on port ${PORT}`);

    testDatabaseConnection();
});