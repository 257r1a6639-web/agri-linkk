require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// ===============================
// DATABASE CONNECTION
// ===============================

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((error) => {
    if (error) {
        console.error("MySQL connection failed:", error);
        return;
    }

    console.log("MySQL connected successfully!");
});

// ===============================
// JWT SECRET
// ===============================

const JWT_SECRET = process.env.JWT_SECRET;

// ===============================
// TEST ROUTE
// ===============================

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "AGRI LINKK API is running successfully!"
    });
});

app.get("/test-db", (req, res) => {
    db.query("SELECT 1 AS test", (error, results) => {
        if (error) {
            console.error(error);

            return res.status(500).json({
                success: false,
                message: "Database connection failed"
            });
        }

        res.json({
            success: true,
            message: "Database connected successfully!",
            result: results
        });
    });
});

// ===============================
// JWT AUTHENTICATION MIDDLEWARE
// ===============================

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    const token =
        authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Access token required"
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token"
            });
        }

        req.user = user;
        next();
    });
}

// ===============================
// ADMIN AUTHENTICATION
// ===============================

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

// ===============================
// REGISTER
// ===============================

app.post("/api/register", async (req, res) => {
    try {
        const {
            fullName,
            email,
            phone,
            role,
            password
        } = req.body;

        if (
            !fullName ||
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

        db.query(
            "SELECT id FROM users WHERE email = ?",
            [email],
            async (error, results) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                if (results.length > 0) {
                    return res.status(409).json({
                        success: false,
                        message: "Email already registered"
                    });
                }

                const hashedPassword =
                    await bcrypt.hash(password, 10);

                const sql = `
                    INSERT INTO users
                    (full_name, email, phone, role, password)
                    VALUES (?, ?, ?, ?, ?)
                `;

                db.query(
                    sql,
                    [
                        fullName,
                        email,
                        phone,
                        role,
                        hashedPassword
                    ],
                    (insertError, result) => {
                        if (insertError) {
                            console.error(insertError);

                            return res.status(500).json({
                                success: false,
                                message: "Registration failed"
                            });
                        }

                        res.status(201).json({
                            success: true,
                            message:
                                "Registration successful",
                            userId: result.insertId
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/login", (req, res) => {
    const {
        email,
        password,
        role
    } = req.body;

    if (!email || !password || !role) {
        return res.status(400).json({
            success: false,
            message: "Email, password and role are required"
        });
    }

    const sql = `
        SELECT
            id,
            full_name,
            email,
            phone,
            role,
            password
        FROM users
        WHERE email = ?
          AND role = ?
    `;

    db.query(
        sql,
        [email, role],
        async (error, results) => {
            if (error) {
                console.error(error);

                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            if (results.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid email, password or role"
                });
            }

            const user = results[0];

            const passwordMatch =
                await bcrypt.compare(
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
                token: token,
                user: user
            });
        }
    );
});

// ===============================
// FARM DETAILS - SAVE / UPDATE
// ===============================

app.post(
    "/api/farm-details",
    authenticateToken,
    (req, res) => {
        if (req.user.role !== "Farmer") {
            return res.status(403).json({
                success: false,
                message: "Only farmers can save farm details"
            });
        }

        const {
            landArea,
            landLocation,
            cropName,
            farmingType
        } = req.body;

        if (
            landArea === undefined ||
            !landLocation ||
            !cropName ||
            !farmingType
        ) {
            return res.status(400).json({
                success: false,
                message: "All farm details are required"
            });
        }

        const checkSql = `
            SELECT id
            FROM farmers
            WHERE user_id = ?
        `;

        db.query(
            checkSql,
            [req.user.id],
            (error, results) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                if (results.length > 0) {
                    const updateSql = `
                        UPDATE farmers
                        SET
                            land_area = ?,
                            land_location = ?,
                            crop_name = ?,
                            farming_type = ?
                        WHERE user_id = ?
                    `;

                    db.query(
                        updateSql,
                        [
                            landArea,
                            landLocation,
                            cropName,
                            farmingType,
                            req.user.id
                        ],
                        (updateError) => {
                            if (updateError) {
                                console.error(updateError);

                                return res.status(500).json({
                                    success: false,
                                    message:
                                        "Failed to update farm details"
                                });
                            }

                            res.json({
                                success: true,
                                message:
                                    "Farm details updated successfully"
                            });
                        }
                    );
                } else {
                    const insertSql = `
                        INSERT INTO farmers
                        (
                            user_id,
                            land_area,
                            land_location,
                            crop_name,
                            farming_type
                        )
                        VALUES (?, ?, ?, ?, ?)
                    `;

                    db.query(
                        insertSql,
                        [
                            req.user.id,
                            landArea,
                            landLocation,
                            cropName,
                            farmingType
                        ],
                        (insertError) => {
                            if (insertError) {
                                console.error(insertError);

                                return res.status(500).json({
                                    success: false,
                                    message:
                                        "Failed to save farm details"
                                });
                            }

                            res.status(201).json({
                                success: true,
                                message:
                                    "Farm details saved successfully"
                            });
                        }
                    );
                }
            }
        );
    }
);

// ===============================
// GET FARM DETAILS
// ===============================

app.get(
    "/api/farm-details",
    authenticateToken,
    (req, res) => {
        if (req.user.role !== "Farmer") {
            return res.status(403).json({
                success: false,
                message: "Only farmers can access farm details"
            });
        }

        const sql = `
            SELECT
                id,
                land_area,
                land_location,
                crop_name,
                farming_type
            FROM farmers
            WHERE user_id = ?
        `;

        db.query(
            sql,
            [req.user.id],
            (error, results) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message: "Failed to load farm details"
                    });
                }

                res.json({
                    success: true,
                    farm: results.length > 0
                        ? results[0]
                        : null
                });
            }
        );
    }
);

// ===============================
// ADD PRODUCT
// ===============================

app.post(
    "/api/products",
    authenticateToken,
    (req, res) => {
        if (req.user.role !== "Farmer") {
            return res.status(403).json({
                success: false,
                message: "Only farmers can add products"
            });
        }

        const {
            productName,
            quantity,
            grade,
            price,
            description
        } = req.body;

        if (
            !productName ||
            quantity === undefined ||
            !grade ||
            price === undefined
        ) {
            return res.status(400).json({
                success: false,
                message: "Product details are required"
            });
        }

        const farmerSql = `
            SELECT id
            FROM farmers
            WHERE user_id = ?
        `;

        db.query(
            farmerSql,
            [req.user.id],
            (error, farmerResults) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                if (farmerResults.length === 0) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Please save your farm details first"
                    });
                }

                const farmerId =
                    farmerResults[0].id;

                const sql = `
                    INSERT INTO products
                    (
                        farmer_id,
                        product_name,
                        quantity,
                        grade,
                        price,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                `;

                db.query(
                    sql,
                    [
                        farmerId,
                        productName,
                        quantity,
                        grade,
                        price,
                        description || ""
                    ],
                    (insertError, result) => {
                        if (insertError) {
                            console.error(insertError);

                            return res.status(500).json({
                                success: false,
                                message:
                                    "Failed to add product"
                            });
                        }

                        res.status(201).json({
                            success: true,
                            message:
                                "Product added successfully",
                            productId: result.insertId
                        });
                    }
                );
            }
        );
    }
);

// ===============================
// GET FARMER'S PRODUCTS
// ===============================

app.get(
    "/api/products",
    authenticateToken,
    (req, res) => {
        if (req.user.role !== "Farmer") {
            return res.status(403).json({
                success: false,
                message: "Only farmers can access their products"
            });
        }

        const sql = `
            SELECT
                p.id,
                p.product_name,
                p.quantity,
                p.grade,
                p.price,
                p.description,
                p.created_at
            FROM products p
            INNER JOIN farmers f
                ON p.farmer_id = f.id
            WHERE f.user_id = ?
            ORDER BY p.created_at DESC
        `;

        db.query(
            sql,
            [req.user.id],
            (error, products) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message: "Failed to load products"
                    });
                }

                res.json({
                    success: true,
                    products: products
                });
            }
        );
    }
);

// ===============================
// MARKETPLACE PRODUCTS
// ===============================

app.get(
    "/api/market-products",
    authenticateToken,
    (req, res) => {
        const allowedRoles = [
            "MSME",
            "Logistics",
            "Community",
            "Apartment"
        ];

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message:
                    "You do not have access to the marketplace"
            });
        }

        const sql = `
            SELECT
                p.id,
                p.product_name,
                p.quantity,
                p.grade,
                p.price,
                p.description,
                p.created_at,

                u.full_name AS farmer_name,
                u.phone AS farmer_phone,

                f.land_location,
                f.crop_name,
                f.farming_type

            FROM products p

            INNER JOIN farmers f
                ON p.farmer_id = f.id

            INNER JOIN users u
                ON f.user_id = u.id

            ORDER BY p.created_at DESC
        `;

        db.query(
            sql,
            (error, products) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message:
                            "Failed to load marketplace products"
                    });
                }

                res.json({
                    success: true,
                    products: products
                });
            }
        );
    }
);

// ===============================
// DELETE PRODUCT
// ===============================

app.delete(
    "/api/products/:productId",
    authenticateToken,
    (req, res) => {
        if (req.user.role !== "Farmer") {
            return res.status(403).json({
                success: false,
                message: "Only farmers can delete products"
            });
        }

        const productId =
            req.params.productId;

        const checkSql = `
            SELECT p.id
            FROM products p
            INNER JOIN farmers f
                ON p.farmer_id = f.id
            WHERE p.id = ?
              AND f.user_id = ?
        `;

        db.query(
            checkSql,
            [
                productId,
                req.user.id
            ],
            (error, results) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                if (results.length === 0) {
                    return res.status(404).json({
                        success: false,
                        message:
                            "Product not found or access denied"
                    });
                }

                const deleteSql = `
                    DELETE FROM products
                    WHERE id = ?
                `;

                db.query(
                    deleteSql,
                    [productId],
                    (deleteError) => {
                        if (deleteError) {
                            console.error(deleteError);

                            return res.status(500).json({
                                success: false,
                                message:
                                    "Failed to delete product"
                            });
                        }

                        res.json({
                            success: true,
                            message:
                                "Product deleted successfully"
                        });
                    }
                );
            }
        );
    }
);

// ===============================
// ADMIN - GET ALL USERS
// ===============================

app.get(
    "/api/admin/users",
    authenticateAdmin,
    (req, res) => {
        const sql = `
            SELECT
                id,
                full_name,
                email,
                phone,
                role,
                created_at
            FROM users
            ORDER BY created_at DESC
        `;

        db.query(
            sql,
            (error, users) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message:
                            "Failed to load users"
                    });
                }

                res.json({
                    success: true,
                    users: users
                });
            }
        );
    }
);

// ===============================
// ADMIN - GET ALL PRODUCTS
// ===============================

app.get(
    "/api/admin/products",
    authenticateAdmin,
    (req, res) => {
        const sql = `
            SELECT
                p.id,
                p.product_name,
                p.quantity,
                p.grade,
                p.price,
                p.description,
                p.created_at,

                u.full_name AS farmer_name,
                u.phone AS farmer_phone,

                f.land_location,
                f.crop_name,
                f.farming_type

            FROM products p

            INNER JOIN farmers f
                ON p.farmer_id = f.id

            INNER JOIN users u
                ON f.user_id = u.id

            ORDER BY p.created_at DESC
        `;

        db.query(
            sql,
            (error, products) => {
                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        success: false,
                        message:
                            "Failed to load products"
                    });
                }

                res.json({
                    success: true,
                    products: products
                });
            }
        );
    }
);

// ===============================
// 404 ROUTE
// ===============================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "API route not found"
    });
});

// ===============================
// SERVER
// ===============================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(
        `AGRI LINKK server running on port ${PORT}`
    );
});