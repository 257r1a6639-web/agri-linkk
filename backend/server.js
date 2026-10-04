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
// MYSQL CONNECTION POOL
// ========================================

const db = mysql.createPool({

    host: process.env.DB_HOST,

    user: process.env.DB_USER,

    password: process.env.DB_PASSWORD,

    database: process.env.DB_NAME,

    waitForConnections: true,

    connectionLimit: 10,

    queueLimit: 0,

    connectTimeout: 20000,

    enableKeepAlive: true,

    keepAliveInitialDelay: 0

});


// ========================================
// TEST MYSQL CONNECTION
// ========================================

db.getConnection((error, connection) => {

    if (error) {

        console.error(
            "MySQL connection failed:",
            error
        );

        return;
    }

    console.log(
        "MySQL connected successfully!"
    );

    connection.release();

});


// ========================================
// JWT SECRET
// ========================================

const JWT_SECRET =
    process.env.JWT_SECRET;


// ========================================
// HOME ROUTE
// ========================================

app.get("/", (req, res) => {

    res.json({

        success: true,

        message:
            "AGRI LINKK API is running successfully!"

    });

});


// ========================================
// TEST DATABASE
// ========================================

app.get("/test-db", (req, res) => {

    db.query(
        "SELECT 1 AS test",

        (error, results) => {

            if (error) {

                console.error(
                    "Database test error:",
                    error
                );

                return res.status(500).json({

                    success: false,

                    message:
                        "Database connection failed"

                });

            }

            res.json({

                success: true,

                message:
                    "Database connected successfully!",

                result: results

            });

        }

    );

});


// ========================================
// AUTHENTICATE TOKEN
// ========================================

function authenticateToken(
    req,
    res,
    next
) {

    const authHeader =
        req.headers["authorization"];

    const token =
        authHeader &&
        authHeader.split(" ")[1];


    if (!token) {

        return res.status(401).json({

            success: false,

            message:
                "Access token required"

        });

    }


    jwt.verify(
        token,
        JWT_SECRET,

        (error, user) => {

            if (error) {

                return res.status(403).json({

                    success: false,

                    message:
                        "Invalid or expired token"

                });

            }


            req.user = user;

            next();

        }

    );

}


// ========================================
// AUTHENTICATE ADMIN
// ========================================

function authenticateAdmin(
    req,
    res,
    next
) {

    authenticateToken(
        req,
        res,

        () => {

            if (
                req.user.role !==
                "Admin"
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "Admin access required"

                });

            }

            next();

        }

    );

}


// ========================================
// REGISTER
// ========================================

app.post(
    "/api/register",

    async (req, res) => {

        try {

            const {
                full_name,
                email,
                phone,
                role,
                password
            } = req.body;


            // -----------------------------
            // VALIDATION
            // -----------------------------

            if (
                !full_name ||
                !email ||
                !phone ||
                !role ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "All fields are required"

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


            if (
                !validRoles.includes(role)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid role"

                });

            }


            if (
                password.length < 6
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Password must contain at least 6 characters"

                });

            }


            // -----------------------------
            // CHECK EXISTING EMAIL
            // -----------------------------

            db.query(

                "SELECT id FROM users WHERE email = ?",

                [email],

                async (checkError, users) => {

                    if (checkError) {

                        console.error(
                            "Registration database error:",
                            checkError
                        );

                        return res.status(500).json({

                            success: false,

                            message:
                                "Database error"

                        });

                    }


                    if (users.length > 0) {

                        return res.status(409).json({

                            success: false,

                            message:
                                "Email already registered"

                        });

                    }


                    // -----------------------------
                    // HASH PASSWORD
                    // -----------------------------

                    const hashedPassword =
                        await bcrypt.hash(
                            password,
                            10
                        );


                    // -----------------------------
                    // INSERT USER
                    // -----------------------------

                    db.query(

                        `INSERT INTO users
                        (
                            full_name,
                            email,
                            phone,
                            role,
                            password
                        )
                        VALUES (?, ?, ?, ?, ?)`,

                        [
                            full_name,
                            email,
                            phone,
                            role,
                            hashedPassword
                        ],

                        (insertError, result) => {

                            if (insertError) {

                                console.error(
                                    "Registration insert error:",
                                    insertError
                                );

                                return res.status(500).json({

                                    success: false,

                                    message:
                                        "Database error"

                                });

                            }


                            res.status(201).json({

                                success: true,

                                message:
                                    "Registration successful",

                                userId:
                                    result.insertId

                            });

                        }

                    );

                }

            );

        }

        catch (error) {

            console.error(
                "Registration error:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }

);


// ========================================
// LOGIN
// ========================================

app.post(
    "/api/login",

    (req, res) => {

        const {
            email,
            password,
            role
        } = req.body;


        // -----------------------------
        // VALIDATION
        // -----------------------------

        if (
            !email ||
            !password ||
            !role
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Email, password and role are required"

            });

        }


        // -----------------------------
        // FIND USER
        // -----------------------------

        db.query(

            `SELECT
                id,
                full_name,
                email,
                phone,
                role,
                password,
                created_at
             FROM users
             WHERE email = ?
             AND role = ?`,

            [
                email,
                role
            ],

            async (error, users) => {

                if (error) {

                    console.error(
                        "Login database error:",
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                if (
                    users.length === 0
                ) {

                    return res.status(401).json({

                        success: false,

                        message:
                            "Invalid email, password or role"

                    });

                }


                const user =
                    users[0];


                // -----------------------------
                // CHECK PASSWORD
                // -----------------------------

                const passwordMatch =
                    await bcrypt.compare(
                        password,
                        user.password
                    );


                if (!passwordMatch) {

                    return res.status(401).json({

                        success: false,

                        message:
                            "Invalid email, password or role"

                    });

                }


                // -----------------------------
                // CREATE JWT
                // -----------------------------

                const token =
                    jwt.sign(

                        {
                            id: user.id,

                            email: user.email,

                            role: user.role

                        },

                        JWT_SECRET,

                        {
                            expiresIn:
                                "24h"
                        }

                    );


                // -----------------------------
                // REMOVE PASSWORD
                // -----------------------------

                delete user.password;


                // -----------------------------
                // RESPONSE
                // -----------------------------

                res.json({

                    success: true,

                    message:
                        "Login successful",

                    token: token,

                    user: user

                });

            }

        );

    }

);


// ========================================
// FARMER - SAVE FARM DETAILS
// ========================================

app.post(
    "/api/farm-details",

    authenticateToken,

    (req, res) => {

        const {
            land_area,
            land_location,
            crop_name,
            farming_type
        } = req.body;


        if (
            req.user.role !==
            "Farmer"
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "Farmer access required"

            });

        }


        db.query(

            `SELECT id
             FROM farmers
             WHERE user_id = ?`,

            [req.user.id],

            (findError, farmers) => {

                if (findError) {

                    console.error(
                        findError
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                if (
                    farmers.length > 0
                ) {

                    db.query(

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
                        ],

                        (updateError) => {

                            if (updateError) {

                                console.error(
                                    updateError
                                );

                                return res.status(500).json({

                                    success: false,

                                    message:
                                        "Database error"

                                });

                            }


                            res.json({

                                success: true,

                                message:
                                    "Farm details updated successfully"

                            });

                        }

                    );

                }

                else {

                    db.query(

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
                        ],

                        (insertError) => {

                            if (insertError) {

                                console.error(
                                    insertError
                                );

                                return res.status(500).json({

                                    success: false,

                                    message:
                                        "Database error"

                                });

                            }


                            res.json({

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


// ========================================
// FARMER - GET FARM DETAILS
// ========================================

app.get(
    "/api/farm-details",

    authenticateToken,

    (req, res) => {

        if (
            req.user.role !==
            "Farmer"
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "Farmer access required"

            });

        }


        db.query(

            `SELECT *
             FROM farmers
             WHERE user_id = ?`,

            [req.user.id],

            (error, results) => {

                if (error) {

                    console.error(
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                res.json({

                    success: true,

                    farm:
                        results.length > 0
                            ? results[0]
                            : null

                });

            }

        );

    }

);


// ========================================
// FARMER - ADD PRODUCT
// ========================================

app.post(
    "/api/products",

    authenticateToken,

    (req, res) => {

        if (
            req.user.role !==
            "Farmer"
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "Farmer access required"

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
            !quantity ||
            !grade ||
            !price
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Product name, quantity, grade and price are required"

            });

        }


        db.query(

            `SELECT id
             FROM farmers
             WHERE user_id = ?`,

            [req.user.id],

            (farmerError, farmers) => {

                if (farmerError) {

                    console.error(
                        farmerError
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                if (
                    farmers.length === 0
                ) {

                    return res.status(400).json({

                        success: false,

                        message:
                            "Please save your farm details first"

                    });

                }


                const farmerId =
                    farmers[0].id;


                db.query(

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
                        farmerId,
                        product_name,
                        quantity,
                        grade,
                        price,
                        description || ""
                    ],

                    (error, result) => {

                        if (error) {

                            console.error(
                                error
                            );

                            return res.status(500).json({

                                success: false,

                                message:
                                    "Database error"

                            });

                        }


                        res.status(201).json({

                            success: true,

                            message:
                                "Product added successfully",

                            productId:
                                result.insertId

                        });

                    }

                );

            }

        );

    }

);


// ========================================
// FARMER - GET OWN PRODUCTS
// ========================================

app.get(
    "/api/products",

    authenticateToken,

    (req, res) => {

        if (
            req.user.role !==
            "Farmer"
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "Farmer access required"

            });

        }


        db.query(

            `SELECT
                p.*,
                f.crop_name,
                f.farming_type
             FROM products p
             JOIN farmers f
             ON p.farmer_id = f.id
             WHERE f.user_id = ?
             ORDER BY p.created_at DESC`,

            [req.user.id],

            (error, products) => {

                if (error) {

                    console.error(
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                res.json({

                    success: true,

                    products:
                        products

                });

            }

        );

    }

);


// ========================================
// MARKET PRODUCTS
// ========================================

app.get(
    "/api/market-products",

    authenticateToken,

    (req, res) => {

        db.query(

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

             JOIN farmers f
             ON p.farmer_id = f.id

             JOIN users u
             ON f.user_id = u.id

             ORDER BY p.created_at DESC`,

            (error, products) => {

                if (error) {

                    console.error(
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                res.json({

                    success: true,

                    products:
                        products

                });

            }

        );

    }

);


// ========================================
// DELETE PRODUCT
// ========================================

app.delete(
    "/api/products/:productId",

    authenticateToken,

    (req, res) => {

        if (
            req.user.role !==
            "Farmer"
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "Farmer access required"

            });

        }


        const productId =
            req.params.productId;


        db.query(

            `DELETE p
             FROM products p

             JOIN farmers f
             ON p.farmer_id = f.id

             WHERE p.id = ?
             AND f.user_id = ?`,

            [
                productId,
                req.user.id
            ],

            (error, result) => {

                if (error) {

                    console.error(
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                if (
                    result.affectedRows === 0
                ) {

                    return res.status(404).json({

                        success: false,

                        message:
                            "Product not found"

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


// ========================================
// ADMIN - GET ALL USERS
// ========================================

app.get(
    "/api/admin/users",

    authenticateAdmin,

    (req, res) => {

        db.query(

            `SELECT
                id,
                full_name,
                email,
                phone,
                role,
                created_at
             FROM users
             ORDER BY created_at DESC`,

            (error, users) => {

                if (error) {

                    console.error(
                        "Admin users database error:",
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                res.json({

                    success: true,

                    users:
                        users

                });

            }

        );

    }

);


// ========================================
// ADMIN - GET ALL PRODUCTS
// ========================================

app.get(
    "/api/admin/products",

    authenticateAdmin,

    (req, res) => {

        db.query(

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

             JOIN farmers f
             ON p.farmer_id = f.id

             JOIN users u
             ON f.user_id = u.id

             ORDER BY p.created_at DESC`,

            (error, products) => {

                if (error) {

                    console.error(
                        "Admin products database error:",
                        error
                    );

                    return res.status(500).json({

                        success: false,

                        message:
                            "Database error"

                    });

                }


                res.json({

                    success: true,

                    products:
                        products

                });

            }

        );

    }

);


// ========================================
// GLOBAL ERROR HANDLER
// ========================================

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled server error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Internal server error"

        });

    }
);


// ========================================
// SERVER
// ========================================

const PORT =
    process.env.PORT || 5000;


app.listen(
    PORT,

    () => {

        console.log(
            `AGRI LINKK server running on port ${PORT}`
        );

    }

);