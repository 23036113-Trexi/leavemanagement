const express= require('express');
const mysql = require('mysql2');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const ExcelJS = require('exceljs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const app = express();

// Password hashing configuration
const SALT_ROUNDS = 12;

// Helper function to hash passwords
async function hashPassword(plainPassword) {
    try {
        const hashedPassword = await bcrypt.hash(plainPassword, SALT_ROUNDS);
        return hashedPassword;
    } catch (error) {
        console.error('Error hashing password:', error);
        throw error;
    }
}

// Password reset token generation and validation functions
function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

function validateTokenFormat(token) {
    return /^[a-f0-9]{64}$/.test(token);
}

async function createPasswordResetToken(userId) {
    const token = generateResetToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now
    
    try {
        await db.promise().execute(
            `INSERT INTO password_reset_tokens (user_id, token, expires_at) 
             VALUES (?, ?, ?)`,
            [userId, token, expiresAt]
        );
        return token;
    } catch (error) {
        console.error('Error creating password reset token:', error);
        throw error;
    }
}

async function validateResetToken(token) {
    if (!validateTokenFormat(token)) {
        return { valid: false, error: 'Invalid token format' };
    }

    try {
        const [rows] = await db.promise().execute(
            `SELECT prt.*, u.email, u.id as user_id 
             FROM password_reset_tokens prt
             JOIN users u ON prt.user_id = u.id
             WHERE prt.token = ? AND prt.used = 0 AND prt.expires_at > NOW()`,
            [token]
        );

        if (rows.length === 0) {
            return { valid: false, error: 'Token not found, expired, or already used' };
        }

        return { 
            valid: true, 
            userId: rows[0].user_id,
            email: rows[0].email,
            tokenId: rows[0].id
        };
    } catch (error) {
        console.error('Error validating reset token:', error);
        return { valid: false, error: 'Database error' };
    }
}

async function markTokenAsUsed(tokenId) {
    try {
        await db.promise().execute(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = ?',
            [tokenId]
        );
    } catch (error) {
        console.error('Error marking token as used:', error);
        throw error;
    }
}

// File upload configuration with multer
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'document-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf', 
                         'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only JPG, PNG, PDF, DOC, and DOCX files are allowed.'), false);
    }
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: fileFilter
});

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', './views');

// middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Session-based authentication middleware
function authenticateUser(req, res, next) {
    // Check if user has valid session
    if (!req.session || !req.session.userId) {
        // For API requests, return JSON error
        if (req.headers.accept && req.headers.accept.includes('application/json')) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required. Please log in.'
            });
        }
        // For web requests, redirect to login page
        return res.redirect('/');
    }
    
    // Add authenticated user info to request object
    req.authenticatedUserId = req.session.userId;
    req.authenticatedUserEmail = req.session.userEmail;
    req.authenticatedUserRole = req.session.userRole;
    req.authenticatedUserName = req.session.userName;
    
    next();
}

// Role-based authorization middleware
function authorizeRole(allowedRoles) {
    return (req, res, next) => {
        // Get user role from session (already verified in authenticateUser)
        const userRole = req.authenticatedUserRole;
        
        if (!userRole) {
            return res.status(401).json({
                success: false,
                message: 'User role not found in session'
            });
        }
        
        if (!allowedRoles.includes(userRole)) {
            // For API requests, return JSON error
            if (req.headers.accept && req.headers.accept.includes('application/json')) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required role: ${allowedRoles.join(' or ')}`
                });
            }
            // For web requests, redirect to login or show error page
            return res.status(403).send('Access denied. Insufficient permissions.');
        }
        
        req.userRole = userRole;
        next();
    };
}

// Manager validation middleware to verify direct report relationships
function validateManagerAccess(req, res, next) {
    const manager_id = req.authenticatedUserId;
    const { request_id } = req.params;
    
    // If no request_id in params, skip validation (for general manager endpoints)
    if (!request_id) {
        return next();
    }
    
    // Query to verify the leave request belongs to a direct report of this manager
    const validationQuery = `
        SELECT lr.id, u.manager_id, u.email as employee_email
        FROM leave_request lr
        JOIN users u ON lr.user_id = u.id
        WHERE lr.id = ? AND u.manager_id = ?
    `;
    
    db.query(validationQuery, [request_id, manager_id], (err, results) => {
        if (err) {
            console.error('Error validating manager access:', err);
            return res.status(500).json({
                success: false,
                message: 'Error validating access permissions'
            });
        }
        
        if (results.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. You can only manage leave requests from your direct reports.'
            });
        }
        
        // Add employee info to request for use in the endpoint
        req.employeeInfo = {
            email: results[0].employee_email
        };
        
        next();
    });
}

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    port: '3316',
    password: '',
    database: 'geolah'
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Session store configuration
const sessionStore = new MySQLStore({
    host: 'localhost',
    port: 3316,
    user: 'root',
    password: '',
    database: 'geolah',
    createDatabaseTable: true,
    schema: {
        tableName: 'sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
});

// Rate limiting for login attempts (brute force protection)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per windowMs
    message: {
        error: 'Too many login attempts. Please try again after 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Skip successful requests
    skipSuccessfulRequests: true,
    // Custom handler for rate limit exceeded
    handler: (req, res) => {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Too many login attempts. Please try again after 15 minutes.',
            success: null
        });
    }
});

// Rate limiter for password reset requests
const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // Limit each IP to 3 forgot password requests per windowMs
    message: {
        error: 'Too many password reset attempts. Please try again after 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'Too many password reset attempts. Please try again after 15 minutes.',
            success: null
        });
    }
});

// Rate limiter for password reset form submission
const resetPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 reset attempts per windowMs
    message: {
        error: 'Too many password reset attempts. Please try again after 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

// Session middleware configuration
app.use(session({
    key: 'geolah_session',
    secret: 'geolah_leave_management_secret_key_2024',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true,
        secure: false // Set to true in production with HTTPS
    }
}));

// GET / - Login page route handler
app.get('/', (req, res) => {
    // Check if user is already logged in
    if (req.session && req.session.userId) {
        return res.redirect('/dashboard');
    }
    
    // Render login page using index.ejs
    res.render('index', {
        title: 'GeoLah - Employee Login',
        error: req.query.error || null,
        success: req.query.success || null
    });
});

// POST /login - Authentication route with rate limiting
app.post('/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;
    
    // Input sanitization and validation
    if (!email || !password) {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Email and password are required',
            success: null
        });
    }
    
    // Trim whitespace and validate field lengths
    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();
    
    if (trimmedEmail.length === 0 || trimmedPassword.length === 0) {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Email and password cannot be empty',
            success: null
        });
    }
    
    // Email length validation (reasonable limit)
    if (trimmedEmail.length > 254) {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Email address is too long',
            success: null
        });
    }
    
    // Password length validation (basic security)
    if (trimmedPassword.length < 3 || trimmedPassword.length > 128) {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Invalid credentials',
            success: null
        });
    }
    
    // Enhanced email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Please enter a valid email address',
            success: null
        });
    }
    
    // Check for potentially malicious characters
    const suspiciousChars = /[<>'"&]/;
    if (suspiciousChars.test(trimmedEmail)) {
        return res.render('index', {
            title: 'GeoLah - Employee Login',
            error: 'Invalid characters in email address',
            success: null
        });
    }
    
    // Query users table for matching email (using parameterized query to prevent SQL injection)
    const userQuery = 'SELECT id, email, password, role, name FROM users WHERE email = ?';
    
    db.query(userQuery, [trimmedEmail], (err, results) => {
        if (err) {
            console.error('Database error during login:', err);
            return res.render('index', {
                title: 'GeoLah - Employee Login',
                error: 'Login failed. Please try again.',
                success: null
            });
        }
        
        // Check if user exists
        if (results.length === 0) {
            console.log(`Failed login attempt for email: ${trimmedEmail} from IP: ${req.ip}`);
            return res.render('index', {
                title: 'GeoLah - Employee Login',
                error: 'Invalid email or password',
                success: null
            });
        }
        
        const user = results[0];
        
        // Verify password using bcrypt
        bcrypt.compare(trimmedPassword, user.password, (err, isMatch) => {
            if (err) {
                console.error('Password comparison error:', err);
                return res.render('index', {
                    title: 'GeoLah - Employee Login',
                    error: 'Login failed. Please try again.',
                    success: null
                });
            }
            
            if (!isMatch) {
                console.log(`Failed password attempt for email: ${trimmedEmail} from IP: ${req.ip}`);
                return res.render('index', {
                    title: 'GeoLah - Employee Login',
                    error: 'Invalid email or password',
                    success: null
                });
            }
            
            // Create user session on successful authentication
            console.log(`Successful login for email: ${trimmedEmail} (ID: ${user.id}, Role: ${user.role}) from IP: ${req.ip}`);
            req.session.userId = user.id;
            req.session.userEmail = user.email;
            req.session.userRole = user.role;
            req.session.userName = user.name;
            
            // Save session and redirect to unified dashboard
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    return res.render('index', {
                        title: 'GeoLah - Employee Login',
                        error: 'Login failed. Please try again.',
                        success: null
                    });
                }
                
                // Redirect to unified dashboard
                res.redirect('/dashboard');
            });
        });
    });
});

// Password Reset Routes

// GET /forgot-password - Display forgot password form
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', {
        title: 'GeoLah - Reset Password',
        error: req.query.error || null,
        success: req.query.success || null
    });
});

// POST /forgot-password - Process simple password reset request
app.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
    const { email, confirmEmail, newPassword, confirmPassword } = req.body;
    
    // Input validation
    if (!email || !confirmEmail || !newPassword || !confirmPassword) {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'All fields are required',
            success: null
        });
    }
    
    const trimmedEmail = email.trim().toLowerCase();
    const trimmedConfirmEmail = confirmEmail.trim().toLowerCase();
    
    // Email format validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(trimmedEmail) || trimmedEmail.length > 254) {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'Please enter a valid email address',
            success: null
        });
    }
    
    // Email confirmation validation
    if (trimmedEmail !== trimmedConfirmEmail) {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'Email addresses do not match',
            success: null
        });
    }
    
    // Password validation
    if (newPassword !== confirmPassword) {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'Passwords do not match',
            success: null
        });
    }
    
    if (newPassword.length < 8) {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'Password must be at least 8 characters long',
            success: null
        });
    }
    
    // XSS prevention
    if (/[<>'"&]/.test(trimmedEmail) || /[<>'"&]/.test(newPassword)) {
        return res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'Invalid characters detected',
            success: null
        });
    }
    
    try {
        // Check if user exists and is active
        const [userRows] = await db.promise().execute(
            'SELECT id, email, active FROM users WHERE email = ?',
            [trimmedEmail]
        );
        
        if (userRows.length === 0 || userRows[0].active !== 1) {
            return res.render('forgot-password', {
                title: 'GeoLah - Reset Password',
                error: 'Email address not found or account is inactive',
                success: null
            });
        }
        
        const userId = userRows[0].id;
        
        // Hash the new password
        const hashedPassword = await hashPassword(newPassword);
        
        // Update the password in database
        await db.promise().execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, userId]
        );
        
        // Log successful password reset
        console.log(`Password reset successful for user ID: ${userId}, email: ${trimmedEmail}, IP: ${req.ip}`);
        
        // Redirect to login with success message
        res.redirect('/?success=' + encodeURIComponent('Password reset successful. Please log in with your new password.'));
        
    } catch (error) {
        console.error('Error in password reset:', error);
        res.render('forgot-password', {
            title: 'GeoLah - Reset Password',
            error: 'An error occurred while resetting your password. Please try again.',
            success: null
        });
    }
});

// GET /reset-password/:token - Display password reset form
app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    
    try {
        const validation = await validateResetToken(token);
        
        if (!validation.valid) {
            console.log(`Invalid reset token attempted: ${token}, IP: ${req.ip}, error: ${validation.error}`);
            return res.redirect('/login?error=' + encodeURIComponent('Invalid or expired reset link. Please request a new password reset.'));
        }

        // Render password reset form
        res.render('reset-password', {
            title: 'GeoLah - Set New Password',
            token: token,
            email: validation.email,
            error: req.query.error || null
        });

    } catch (error) {
        console.error('Error validating reset token:', error);
        res.redirect('/login?error=' + encodeURIComponent('An error occurred. Please try again.'));
    }
});

// POST /reset-password/:token - Process password reset
app.post('/reset-password/:token', resetPasswordLimiter, async (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;
    
    try {
        // Validate token first
        const validation = await validateResetToken(token);
        
        if (!validation.valid) {
            console.log(`Invalid reset token in POST: ${token}, IP: ${req.ip}, error: ${validation.error}`);
            return res.redirect('/login?error=' + encodeURIComponent('Invalid or expired reset link. Please request a new password reset.'));
        }

        // Password validation
        if (!password || !confirmPassword) {
            return res.render('reset-password', {
                title: 'GeoLah - Set New Password',
                token: token,
                email: validation.email,
                error: 'Both password fields are required'
            });
        }

        if (password !== confirmPassword) {
            return res.render('reset-password', {
                title: 'GeoLah - Set New Password',
                token: token,
                email: validation.email,
                error: 'Passwords do not match'
            });
        }

        // Password strength validation
        if (password.length < 8) {
            return res.render('reset-password', {
                title: 'GeoLah - Set New Password',
                token: token,
                email: validation.email,
                error: 'Password must be at least 8 characters long'
            });
        }

        // XSS prevention
        if (/[<>'"&]/.test(password)) {
            return res.render('reset-password', {
                title: 'GeoLah - Set New Password',
                token: token,
                email: validation.email,
                error: 'Password contains invalid characters'
            });
        }

        // Start database transaction
        await db.promise().beginTransaction();

        try {
            // Hash the new password
            const hashedPassword = await hashPassword(password);
            
            // Update user password
            await db.promise().execute(
                'UPDATE users SET password = ? WHERE id = ?',
                [hashedPassword, validation.userId]
            );

            // Mark token as used
            await markTokenAsUsed(validation.tokenId);

            // Invalidate all sessions for this user (force re-login)
            await db.promise().execute(
                'DELETE FROM sessions WHERE JSON_EXTRACT(data, "$.userId") = ?',
                [validation.userId]
            );

            // Commit transaction
            await db.promise().commit();

            console.log(`Password successfully reset for user ID: ${validation.userId}, email: ${validation.email}, IP: ${req.ip}`);

            // Redirect to login with success message
            res.redirect('/login?success=' + encodeURIComponent('Password reset successful. Please log in with your new password.'));

        } catch (dbError) {
            // Rollback transaction on error
            await db.promise().rollback();
            throw dbError;
        }

    } catch (error) {
        console.error('Error in password reset:', error);
        res.render('reset-password', {
            title: 'GeoLah - Set New Password',
            token: token,
            email: validation?.email || '',
            error: 'An error occurred while resetting your password. Please try again.'
        });
    }
});

// GET /dashboard - Unified dashboard route handler
app.get('/dashboard', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), (req, res) => {
    // Get user info from session
    const user = {
        id: req.authenticatedUserId,
        email: req.authenticatedUserEmail,
        role: req.authenticatedUserRole,
        name: req.authenticatedUserName
    };
    
    // Render unified dashboard with role-based content
    res.render('employee-dashboard', { 
        title: 'GeoLah Dashboard',
        user: user
    });
});

// GET /leave-request-form - Serve the leave request form page
app.get('/leave-request-form', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), (req, res) => {
    // Fetch available leave types from database
    const query = 'SELECT id, type FROM leave_type';
    
    db.query(query, (err, leaveTypes) => {
        if (err) {
            console.error('Error fetching leave types:', err);
            return res.status(500).send('Error loading leave request form');
        }
        
        // Render the leave request form with leave types
        res.render('leave-request', { 
            leaveTypes: leaveTypes,
            title: 'Submit Leave Request'
        });
    });
});

// GET /leave-types - API endpoint to fetch available leave types
app.get('/leave-types', (req, res) => {
    const query = 'SELECT id, type FROM leave_type';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching leave types:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Error fetching leave types' 
            });
        }
        
        res.json({ 
            success: true, 
            data: results 
        });
    });
});

// GET /uploads/:filename - Serve uploaded files (protected route)
app.get('/uploads/:filename', authenticateUser, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'uploads', filename);
    
    // Validate filename to prevent path traversal attacks
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        return res.status(400).json({
            success: false,
            message: 'Invalid filename'
        });
    }
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({
            success: false,
            message: 'File not found'
        });
    }
    
    // Additional security: verify file is in uploads directory
    const uploadsDir = path.join(__dirname, 'uploads');
    const resolvedFilePath = path.resolve(filePath);
    const resolvedUploadsDir = path.resolve(uploadsDir);
    
    if (!resolvedFilePath.startsWith(resolvedUploadsDir)) {
        return res.status(403).json({
            success: false,
            message: 'Access denied'
        });
    }
    
    // Set appropriate content type
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'application/octet-stream';
    
    switch(ext) {
        case '.jpg':
        case '.jpeg':
            contentType = 'image/jpeg';
            break;
        case '.png':
            contentType = 'image/png';
            break;
        case '.pdf':
            contentType = 'application/pdf';
            break;
        case '.doc':
            contentType = 'application/msword';
            break;
        case '.docx':
            contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
            break;
    }
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    res.sendFile(resolvedFilePath);
});


// GET /employee/leave-balance - Get employee's leave balance
app.get('/employee/leave-balance', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), (req, res) => {
    const user_id = req.authenticatedUserId;
    
    // Query to get leave balance and entitlements for the user
    const query = 'SELECT annual_leave_balance, medical_leave_balance, other_leave_balance, annual_leave_entitlement, medical_leave_entitlement, other_leave_entitlement FROM leave_balance WHERE user_id = ?';
    
    db.query(query, [user_id], (err, results) => {
        if (err) {
            console.error('Error fetching leave balance:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching leave balance'
            });
        }
        
        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User leave balance not found'
            });
        }
        
        const leaveBalance = results[0];
        
        res.json({
            success: true,
            data: {
                user_id: parseInt(user_id),
                annual_leave_balance: parseFloat(leaveBalance.annual_leave_balance),
                medical_leave_balance: parseFloat(leaveBalance.medical_leave_balance),
                other_leave_balance: parseFloat(leaveBalance.other_leave_balance),
                annual_leave_entitlement: parseFloat(leaveBalance.annual_leave_entitlement),
                medical_leave_entitlement: parseFloat(leaveBalance.medical_leave_entitlement),
                other_leave_entitlement: parseFloat(leaveBalance.other_leave_entitlement)
            }
        });
    });
});

// GET /employee/leave-requests - Get employee's leave requests (including backdated medical leave)
app.get('/employee/leave-requests', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), (req, res) => {
    const user_id = req.authenticatedUserId;
    const { status } = req.query;
    
    // Build query with optional status filter
    let query = `
        SELECT 
            lr.id,
            lr.request_date,
            lr.start_date,
            lr.end_date,
            lr.half_day,
            lr.reason,
            lr.number_of_days,
            lr.image,
            lt.type as leave_type,
            lra.status as approval_status,
            lra.comment as approval_comment
        FROM leave_request lr
        LEFT JOIN leave_type lt ON lr.leave_type_id = lt.id
        LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
        WHERE lr.user_id = ?
    `;
    
    const queryParams = [user_id];
    
    // Add status filter if provided
    if (status && status.trim() !== '') {
        if (status === 'pending') {
            query += ` AND lra.status IS NULL`;
        } else {
            query += ` AND lra.status = ?`;
            queryParams.push(status);
        }
    }
    
    query += ` ORDER BY lr.start_date ASC`;
    
    console.log('Executing query:', query);
    console.log('Query params:', queryParams);
    
    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching leave requests:', err);
            console.error('Failed query was:', query);
            return res.status(500).json({
                success: false,
                message: 'Error fetching leave requests'
            });
        }
        
        // Format the results
        const formattedResults = results.map(request => ({
            id: request.id,
            request_date: request.request_date,
            start_date: request.start_date,
            end_date: request.end_date,
            half_day: request.half_day,
            reason: request.reason,
            number_of_days: parseFloat(request.number_of_days),
            leave_type: request.leave_type,
            approval_status: request.approval_status || 'pending',
            approval_comment: request.approval_comment || null,
            image: request.image || null
        }));
        
        res.json({
            success: true,
            data: {
                user_id: parseInt(user_id),
                upcoming_requests: formattedResults,
                total_requests: formattedResults.length
            }
        });
    });
});


// GET /employee/leave-history - Get employee's leave request history with pagination
app.get('/employee/leave-history', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), (req, res) => {
    const user_id = req.authenticatedUserId;
    const { page = 1, limit = 10, status, leave_type } = req.query;
    
    // Validate pagination parameters
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    
    if (pageNum < 1 || limitNum < 1 || limitNum > 100) {
        return res.status(400).json({
            success: false,
            message: 'Invalid pagination parameters. Page must be >= 1, limit must be 1-100'
        });
    }
    
    const offset = (pageNum - 1) * limitNum;
    
    // Build WHERE clause for filtering
    let whereClause = 'WHERE lr.user_id = ?';
    let queryParams = [user_id];
    
    if (status) {
        if (status === 'pending') {
            whereClause += ' AND (lra.status IS NULL OR lra.status = "")';
        } else if (status === 'approved' || status === 'rejected') {
            whereClause += ' AND lra.status = ?';
            queryParams.push(status);
        }
    }
    
    if (leave_type) {
        whereClause += ' AND lt.type = ?';
        queryParams.push(leave_type);
    }
    
    // Query to get total count for pagination
    const countQuery = `
        SELECT COUNT(*) as total
        FROM leave_request lr
        LEFT JOIN leave_type lt ON lr.leave_type_id = lt.id
        LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
        ${whereClause}
    `;
    
    db.query(countQuery, queryParams, (err, countResult) => {
        if (err) {
            console.error('Error counting leave history:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching leave history count'
            });
        }
        
        const totalRecords = countResult[0].total;
        const totalPages = Math.ceil(totalRecords / limitNum);
        
        // Query to get leave history with pagination
        const historyQuery = `
            SELECT 
                lr.id,
                lr.request_date,
                lr.start_date,
                lr.end_date,
                lr.half_day,
                lr.reason,
                lr.number_of_days,
                lr.image,
                lt.type as leave_type,
                lra.status as approval_status,
                lra.comment as approval_comment
            FROM leave_request lr
            LEFT JOIN leave_type lt ON lr.leave_type_id = lt.id
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            ${whereClause}
            ORDER BY lr.request_date DESC, lr.start_date DESC
            LIMIT ? OFFSET ?
        `;
        
        const historyParams = [...queryParams, limitNum, offset];
        
        db.query(historyQuery, historyParams, (err, results) => {
            if (err) {
                console.error('Error fetching leave history:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error fetching leave history'
                });
            }
            
            // Format the results
            const formattedResults = results.map(request => ({
                id: request.id,
                request_date: request.request_date,
                start_date: request.start_date,
                end_date: request.end_date,
                half_day: request.half_day,
                reason: request.reason,
                number_of_days: parseFloat(request.number_of_days),
                leave_type: request.leave_type,
                approval_status: request.approval_status || 'pending',
                approval_comment: request.approval_comment || null,
                image: request.image || null
            }));
            
            res.json({
                success: true,
                data: {
                    user_id: parseInt(user_id),
                    leave_history: formattedResults,
                    pagination: {
                        current_page: pageNum,
                        total_pages: totalPages,
                        total_records: totalRecords,
                        records_per_page: limitNum,
                        has_next_page: pageNum < totalPages,
                        has_previous_page: pageNum > 1
                    }
                }
            });
        });
    });
});

// Helper function to calculate working days between two dates
function calculateWorkingDays(startDate, endDate, isHalfDay = null) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    if (start > end) {
        return 0;
    }
    
    let workingDays = 0;
    const currentDate = new Date(start);
    
    while (currentDate <= end) {
        const dayOfWeek = currentDate.getDay();
        // Skip weekends (0 = Sunday, 6 = Saturday)
        if (dayOfWeek !== 0 && dayOfWeek !== 6) {
            workingDays++;
        }
        currentDate.setDate(currentDate.getDate() + 1);
    }
    
    // Handle half-day logic
    if (isHalfDay && (isHalfDay === 'AM' || isHalfDay === 'PM')) {
        // If it's a single day and half-day, return 0.5
        if (start.toDateString() === end.toDateString()) {
            return 0.5;
        }
        // If multiple days with half-day option, reduce by 0.5
        workingDays -= 0.5;
    }
    
    return workingDays;
}

// Helper function to get leave balance field based on leave type
function getLeaveBalanceField(leaveTypeId) {
    switch(leaveTypeId) {
        case 1: return 'annual_leave_balance';
        case 2: return 'medical_leave_balance';
        case 3: return 'other_leave_balance';
        default: return null;
    }
}

// POST /submit-leave-request - Process leave request submission
app.post('/submit-leave-request', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), upload.single('supporting_document'), (req, res) => {
    const { leave_type_id, start_date, end_date, half_day, reason } = req.body;
    const user_id = req.authenticatedUserId;
    
    // Basic validation
    if (!leave_type_id || !start_date || !end_date || !user_id) {
        return res.status(400).json({ 
            success: false, 
            message: 'All required fields must be filled' 
        });
    }
    
    // Validate dates
    const startDate = new Date(start_date);
    const endDate = new Date(end_date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Allow backdating for medical leave (leave_type_id = 2), but not for other leave types
    if (startDate < today && parseInt(leave_type_id) !== 2) {
        return res.status(400).json({ 
            success: false, 
            message: 'Start date cannot be in the past' 
        });
    }
    
    if (endDate < startDate) {
        return res.status(400).json({ 
            success: false, 
            message: 'End date cannot be before start date' 
        });
    }
    
    // Calculate number of days
    const numberOfDays = calculateWorkingDays(start_date, end_date, half_day);
    
    if (numberOfDays <= 0) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid date range or no working days selected' 
        });
    }
    
    // Get leave balance field
    const balanceField = getLeaveBalanceField(parseInt(leave_type_id));
    if (!balanceField) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid leave type' 
        });
    }
    
    // Start database transaction
    db.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Database error occurred' 
            });
        }
        
        // Check for overlapping leave requests (only approved and pending requests)
        const overlapQuery = `
            SELECT lr.id, lr.start_date, lr.end_date, lr.leave_type_id 
            FROM leave_request lr
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            WHERE lr.user_id = ? 
            AND (lra.status IS NULL OR lra.status = '' OR lra.status = 'approved')
            AND (
                (lr.start_date <= ? AND lr.end_date >= ?) OR
                (lr.start_date <= ? AND lr.end_date >= ?) OR
                (lr.start_date >= ? AND lr.end_date <= ?)
            )
        `;
        
        db.query(overlapQuery, [
            user_id, 
            start_date, start_date,  // Check if new start falls within existing range
            end_date, end_date,      // Check if new end falls within existing range  
            start_date, end_date     // Check if new range completely encompasses existing range
        ], (err, overlapResult) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Overlap check error:', err);
                    res.status(500).json({ 
                        success: false, 
                        message: 'Error checking for overlapping requests' 
                    });
                });
            }
            
            if (overlapResult.length > 0) {
                const conflictingRequest = overlapResult[0];
                return db.rollback(() => {
                    res.status(400).json({ 
                        success: false, 
                        message: `Leave request overlaps with existing request from ${conflictingRequest.start_date} to ${conflictingRequest.end_date}` 
                    });
                });
            }
            
            // Check available leave balance (excluding approved but not yet taken leave)
            const balanceQuery = `
                SELECT 
                    lb.${balanceField} as total_balance,
                    COALESCE(SUM(CASE 
                        WHEN lra.status = 'approved' AND lr.start_date >= CURDATE() 
                        THEN lr.number_of_days 
                        ELSE 0 
                    END), 0) as approved_pending_days
                FROM leave_balance lb
                LEFT JOIN leave_request lr ON lb.user_id = lr.user_id AND lr.leave_type_id = ?
                LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
                WHERE lb.user_id = ?
                GROUP BY lb.user_id, lb.${balanceField}
            `;
            
            db.query(balanceQuery, [leave_type_id, user_id], (err, balanceResult) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Balance check error:', err);
                    res.status(500).json({ 
                        success: false, 
                        message: 'Error checking leave balance' 
                    });
                });
            }
            
            if (balanceResult.length === 0) {
                return db.rollback(() => {
                    res.status(400).json({ 
                        success: false, 
                        message: 'User leave balance not found' 
                    });
                });
            }
            
            const result = balanceResult[0];
            const totalBalance = result.total_balance;
            const approvedPendingDays = result.approved_pending_days || 0;
            const availableBalance = totalBalance - approvedPendingDays;
            
            if (availableBalance < numberOfDays) {
                return db.rollback(() => {
                    res.status(400).json({ 
                        success: false, 
                        message: `Insufficient leave balance. Available: ${availableBalance} days (${totalBalance} total - ${approvedPendingDays} approved pending), Requested: ${numberOfDays} days` 
                    });
                });
            }
            
            // Insert leave request
            const insertQuery = `
                INSERT INTO leave_request 
                (request_date, leave_type_id, start_date, end_date, half_day, reason, number_of_days, user_id, image) 
                VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            
            const insertValues = [
                leave_type_id,
                start_date,
                end_date,
                half_day || null,
                reason || null,
                numberOfDays,
                user_id,
                req.file ? req.file.filename : null
            ];
            
            db.query(insertQuery, insertValues, (err, insertResult) => {
                if (err) {
                    return db.rollback(() => {
                        console.error('Insert error:', err);
                        res.status(500).json({ 
                            success: false, 
                            message: 'Error submitting leave request' 
                        });
                    });
                }
                
                // Commit transaction (no balance deduction until approved)
                db.commit(async (err) => {
                    if (err) {
                        return db.rollback(() => {
                            console.error('Commit error:', err);
                            res.status(500).json({ 
                                success: false, 
                                message: 'Error finalizing leave request' 
                            });
                        });
                    }
                    
                    res.json({ 
                        success: true, 
                        message: 'Leave request submitted successfully and is pending approval',
                        request_id: insertResult.insertId,
                        days_requested: numberOfDays,
                        status: 'pending'
                    });
                });
            });
        });
        });
    });
});

// DELETE /leave-request/:request_id/cancel - Cancel a leave request
app.delete('/leave-request/:request_id/cancel', authenticateUser, authorizeRole(['employee', 'manager', 'admin']), (req, res) => {
    const { request_id } = req.params;
    
    // Validate request_id parameter
    if (!request_id || isNaN(request_id)) {
        return res.status(400).json({
            success: false,
            message: 'Valid request ID is required'
        });
    }
    
    // Start database transaction
    db.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start error:', err);
            return res.status(500).json({
                success: false,
                message: 'Database error occurred'
            });
        }
        
        // First, get the leave request details to validate and for balance restoration
        const getRequestQuery = `
            SELECT 
                lr.id,
                lr.user_id,
                lr.leave_type_id,
                lr.start_date,
                lr.end_date,
                lr.number_of_days,
                lra.status
            FROM leave_request lr
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            WHERE lr.id = ?
        `;
        
        db.query(getRequestQuery, [request_id], (err, requestResult) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Error fetching request details:', err);
                    res.status(500).json({
                        success: false,
                        message: 'Error fetching request details'
                    });
                });
            }
            
            if (requestResult.length === 0) {
                return db.rollback(() => {
                    res.status(404).json({
                        success: false,
                        message: 'Leave request not found'
                    });
                });
            }
            
            const request = requestResult[0];
            
            // Verify user can only cancel their own requests (unless they're admin/manager)
            if (request.user_id !== req.authenticatedUserId && req.authenticatedUserRole !== 'admin' && req.authenticatedUserRole !== 'manager') {
                return db.rollback(() => {
                    res.status(403).json({
                        success: false,
                        message: 'Access denied. You can only cancel your own leave requests'
                    });
                });
            }
            
            // Check if request can be cancelled
            if (request.status === 'approved') {
                // For approved requests, check if we can still cancel (hasn't started yet)
                const today = new Date();
                const startDate = new Date(request.start_date);
                today.setHours(0, 0, 0, 0);
                
                if (startDate <= today) {
                    return db.rollback(() => {
                        res.status(400).json({
                            success: false,
                            message: 'Cannot cancel approved leave request that has already started or is in the past'
                        });
                    });
                }
            } else if (request.status === 'rejected') {
                return db.rollback(() => {
                    res.status(400).json({
                        success: false,
                        message: 'Cannot cancel rejected request'
                    });
                });
            }
            
            // For future-dated requests, allow cancellation regardless of start date for pending requests
            if (!request.status || request.status === 'pending') {
                // No additional date validation needed for pending requests
            }
            
            // Delete the leave request
            const deleteRequestQuery = 'DELETE FROM leave_request WHERE id = ?';
            db.query(deleteRequestQuery, [request_id], (err) => {
                if (err) {
                    return db.rollback(() => {
                        console.error('Error deleting request:', err);
                        res.status(500).json({
                            success: false,
                            message: 'Error cancelling leave request'
                        });
                    });
                }
                
                // Only restore balance if the request was approved (had balance deducted)
                if (request.status === 'approved') {
                    const balanceField = getLeaveBalanceField(request.leave_type_id);
                    if (!balanceField) {
                        return db.rollback(() => {
                            res.status(500).json({
                                success: false,
                                message: 'Error processing leave type for balance restoration'
                            });
                        });
                    }
                    
                    const restoreBalanceQuery = `UPDATE leave_balance SET ${balanceField} = ${balanceField} + ? WHERE user_id = ?`;
                    db.query(restoreBalanceQuery, [request.number_of_days, request.user_id], (err) => {
                        if (err) {
                            return db.rollback(() => {
                                console.error('Error restoring balance:', err);
                                res.status(500).json({
                                    success: false,
                                    message: 'Error restoring leave balance'
                                });
                            });
                        }
                        
                        // Commit the transaction
                        db.commit((err) => {
                            if (err) {
                                return db.rollback(() => {
                                    console.error('Commit error:', err);
                                    res.status(500).json({
                                        success: false,
                                        message: 'Error finalizing cancellation'
                                    });
                                });
                            }
                            
                            res.json({
                                success: true,
                                message: 'Approved leave request cancelled successfully',
                                restored_days: request.number_of_days
                            });
                        });
                    });
                } else {
                    // For pending requests, just commit (no balance to restore)
                    db.commit((err) => {
                        if (err) {
                            return db.rollback(() => {
                                console.error('Commit error:', err);
                                res.status(500).json({
                                    success: false,
                                    message: 'Error finalizing cancellation'
                                });
                            });
                        }
                        
                        res.json({
                            success: true,
                            message: 'Pending leave request cancelled successfully',
                            restored_days: 0
                        });
                    });
                }
            });
        });
    });
});

// GET /manager/pending-requests - Fetch pending leave requests from direct reports
app.get('/manager/pending-requests', authenticateUser, authorizeRole(['manager', 'admin']), (req, res) => {
    const manager_id = req.authenticatedUserId;
    
    // Query to get pending leave requests from direct reports
    const query = `
        SELECT 
            lr.id,
            lr.request_date,
            lr.start_date,
            lr.end_date,
            lr.half_day,
            lr.reason,
            lr.number_of_days,
            lr.image,
            u.email as employee_email,
            u.name as employee_name,
            u.id as employee_id,
            lt.type as leave_type,
            lra.status as approval_status,
            lra.comment as approval_comment
        FROM leave_request lr
        JOIN users u ON lr.user_id = u.id
        JOIN leave_type lt ON lr.leave_type_id = lt.id
        LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
        WHERE u.manager_id = ? 
        AND (lra.status IS NULL OR lra.status = '')
        ORDER BY lr.request_date DESC
    `;
    
    db.query(query, [manager_id], (err, results) => {
        if (err) {
            console.error('Error fetching pending requests for manager:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching pending leave requests'
            });
        }
        
        // Format the results
        const formattedResults = results.map(request => ({
            id: request.id,
            request_date: request.request_date,
            start_date: request.start_date,
            end_date: request.end_date,
            half_day: request.half_day,
            reason: request.reason,
            number_of_days: parseFloat(request.number_of_days),
            employee_email: request.employee_email,
            employee_name: request.employee_name,
            employee_id: request.employee_id,
            leave_type: request.leave_type,
            approval_status: 'pending',
            approval_comment: request.approval_comment || null,
            image: request.image || null
        }));
        
        res.json({
            success: true,
            data: {
                manager_id: parseInt(manager_id),
                pending_requests: formattedResults,
                total_pending: formattedResults.length
            }
        });
    });
});

// GET /manager/team-requests - Fetch all leave requests from direct reports with filtering
app.get('/manager/team-requests', authenticateUser, authorizeRole(['manager', 'admin']), (req, res) => {
    const manager_id = req.authenticatedUserId;
    const { 
        status, 
        employee_id, 
        leave_type, 
        date_range, 
        start_date, 
        end_date,
        page = 1, 
        limit = 10 
    } = req.query;
    
    // Validate pagination parameters
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    
    if (pageNum < 1 || limitNum < 1 || limitNum > 100) {
        return res.status(400).json({
            success: false,
            message: 'Invalid pagination parameters. Page must be >= 1, limit must be 1-100'
        });
    }
    
    const offset = (pageNum - 1) * limitNum;
    
    // Build WHERE clause dynamically
    let whereClause = 'WHERE u.manager_id = ?';
    let queryParams = [manager_id];
    
    // Status filter
    if (status && status.trim() !== '') {
        if (status === 'pending') {
            whereClause += ' AND (lra.status IS NULL OR lra.status = "")';
        } else if (status === 'approved' || status === 'rejected') {
            whereClause += ' AND lra.status = ?';
            queryParams.push(status);
        }
    }
    
    // Employee filter
    if (employee_id && !isNaN(employee_id)) {
        whereClause += ' AND u.id = ?';
        queryParams.push(parseInt(employee_id));
    }
    
    // Leave type filter
    if (leave_type && leave_type.trim() !== '') {
        whereClause += ' AND LOWER(lt.type) = LOWER(?)';
        queryParams.push(leave_type.trim());
    }
    
    // Date range filter
    if (start_date && end_date) {
        // Validate date format
        const startDateObj = new Date(start_date);
        const endDateObj = new Date(end_date);
        
        if (isNaN(startDateObj.getTime()) || isNaN(endDateObj.getTime())) {
            return res.status(400).json({
                success: false,
                message: 'Invalid date format. Use YYYY-MM-DD format.'
            });
        }
        
        if (startDateObj > endDateObj) {
            return res.status(400).json({
                success: false,
                message: 'Start date cannot be after end date.'
            });
        }
        
        whereClause += ' AND lr.start_date >= ? AND lr.end_date <= ?';
        queryParams.push(start_date, end_date);
    } else if (start_date) {
        const startDateObj = new Date(start_date);
        if (isNaN(startDateObj.getTime())) {
            return res.status(400).json({
                success: false,
                message: 'Invalid start_date format. Use YYYY-MM-DD format.'
            });
        }
        whereClause += ' AND lr.start_date >= ?';
        queryParams.push(start_date);
    } else if (end_date) {
        const endDateObj = new Date(end_date);
        if (isNaN(endDateObj.getTime())) {
            return res.status(400).json({
                success: false,
                message: 'Invalid end_date format. Use YYYY-MM-DD format.'
            });
        }
        whereClause += ' AND lr.end_date <= ?';
        queryParams.push(end_date);
    }
    
    // Count query for pagination
    const countQuery = `
        SELECT COUNT(*) as total
        FROM leave_request lr
        JOIN users u ON lr.user_id = u.id
        JOIN leave_type lt ON lr.leave_type_id = lt.id
        LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
        ${whereClause}
    `;
    
    db.query(countQuery, queryParams, (err, countResult) => {
        if (err) {
            console.error('Error counting team requests for manager:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching request count'
            });
        }
        
        const totalRecords = countResult[0].total;
        const totalPages = Math.ceil(totalRecords / limitNum);
        
        // Main query for requests with pagination
        const mainQuery = `
            SELECT 
                lr.id,
                lr.request_date,
                lr.start_date,
                lr.end_date,
                lr.half_day,
                lr.reason,
                lr.number_of_days,
                lr.image,
                u.email as employee_email,
                u.name as employee_name,
                u.id as employee_id,
                lt.type as leave_type,
                lt.id as leave_type_id,
                lra.status as approval_status,
                lra.comment as approval_comment
            FROM leave_request lr
            JOIN users u ON lr.user_id = u.id
            JOIN leave_type lt ON lr.leave_type_id = lt.id
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            ${whereClause}
            ORDER BY lr.request_date DESC, lr.start_date DESC
            LIMIT ? OFFSET ?
        `;
        
        const finalParams = [...queryParams, limitNum, offset];
        
        db.query(mainQuery, finalParams, (err, results) => {
            if (err) {
                console.error('Error fetching team requests for manager:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error fetching team leave requests'
                });
            }
            
            // Format the results
            const formattedResults = results.map(request => ({
                id: request.id,
                request_date: request.request_date,
                start_date: request.start_date,
                end_date: request.end_date,
                half_day: request.half_day,
                reason: request.reason,
                number_of_days: parseFloat(request.number_of_days),
                employee_email: request.employee_email,
                employee_name: request.employee_name,
                employee_id: request.employee_id,
                leave_type: request.leave_type,
                leave_type_id: request.leave_type_id,
                approval_status: request.approval_status || 'pending',
                approval_comment: request.approval_comment || null,
                image: request.image || null
            }));
            
            res.json({
                success: true,
                data: {
                    manager_id: parseInt(manager_id),
                    team_requests: formattedResults,
                    pagination: {
                        current_page: pageNum,
                        total_pages: totalPages,
                        total_records: totalRecords,
                        records_per_page: limitNum,
                        has_next_page: pageNum < totalPages,
                        has_previous_page: pageNum > 1
                    },
                    filters_applied: {
                        status: status || null,
                        employee_id: employee_id ? parseInt(employee_id) : null,
                        leave_type: leave_type || null,
                        start_date: start_date || null,
                        end_date: end_date || null
                    }
                }
            });
        });
    });
});

// GET /manager/export-team-requests - Export team leave requests to Excel
app.get('/manager/export-team-requests', authenticateUser, authorizeRole(['manager', 'admin']), async (req, res) => {
    const manager_id = req.authenticatedUserId;
    const { 
        status, 
        employee_id, 
        leave_type, 
        start_date, 
        end_date 
    } = req.query;
    
    try {
        // Build WHERE clause for filtering (same logic as team-requests endpoint)
        let whereClause = 'WHERE u.manager_id = ?';
        let queryParams = [manager_id];
        
        // Status filter
        if (status && status.trim() !== '') {
            if (status === 'pending') {
                whereClause += ' AND (lra.status IS NULL OR lra.status = "")';
            } else if (status === 'approved' || status === 'rejected') {
                whereClause += ' AND lra.status = ?';
                queryParams.push(status);
            }
        }
        
        // Employee filter
        if (employee_id && !isNaN(employee_id)) {
            whereClause += ' AND u.id = ?';
            queryParams.push(parseInt(employee_id));
        }
        
        // Leave type filter
        if (leave_type && leave_type.trim() !== '') {
            whereClause += ' AND lt.type = ?';
            queryParams.push(leave_type.trim());
        }
        
        // Date range filters
        if (start_date) {
            const startDateObj = new Date(start_date);
            if (isNaN(startDateObj.getTime())) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid start_date format. Use YYYY-MM-DD format.'
                });
            }
            whereClause += ' AND lr.start_date >= ?';
            queryParams.push(start_date);
        }
        
        if (end_date) {
            const endDateObj = new Date(end_date);
            if (isNaN(endDateObj.getTime())) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid end_date format. Use YYYY-MM-DD format.'
                });
            }
            whereClause += ' AND lr.end_date <= ?';
            queryParams.push(end_date);
        }
        
        // Get main leave requests data
        const mainQuery = `
            SELECT 
                lr.id as request_id,
                lr.request_date,
                lr.start_date,
                lr.end_date,
                lr.half_day,
                lr.reason,
                lr.number_of_days,
                u.email as employee_email,
                u.name as employee_name,
                u.id as employee_id,
                lt.type as leave_type,
                lt.id as leave_type_id,
                lra.status as approval_status,
                lra.comment as manager_comment
            FROM leave_request lr
            JOIN users u ON lr.user_id = u.id
            JOIN leave_type lt ON lr.leave_type_id = lt.id
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            ${whereClause}
            ORDER BY u.name ASC, lr.request_date DESC
        `;
        
        // Execute query to get leave requests data
        const leaveRequests = await new Promise((resolve, reject) => {
            db.query(mainQuery, queryParams, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        if (leaveRequests.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'No leave requests found for the specified criteria'
            });
        }
        
        // Get unique employee IDs for balance queries
        const employeeIds = [...new Set(leaveRequests.map(req => req.employee_id))];
        
        // Get leave balances for all employees
        const balanceQuery = `
            SELECT 
                lb.user_id as employee_id,
                lb.annual_leave_balance,
                lb.medical_leave_balance,
                lb.other_leave_balance
            FROM leave_balance lb
            WHERE lb.user_id IN (${employeeIds.map(() => '?').join(',')})
        `;
        
        const leaveBalances = await new Promise((resolve, reject) => {
            db.query(balanceQuery, employeeIds, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Create balance lookup map
        const balanceMap = {};
        leaveBalances.forEach(balance => {
            balanceMap[balance.employee_id] = balance;
        });
        
        // Get total leave taken year-to-date for all employees
        const ytdQuery = `
            SELECT 
                lr.user_id as employee_id,
                lt.type as leave_type,
                COALESCE(SUM(
                    CASE 
                        WHEN lra.status = 'approved' 
                        AND YEAR(lr.start_date) = YEAR(CURDATE())
                        THEN lr.number_of_days 
                        ELSE 0 
                    END
                ), 0) as total_taken_ytd
            FROM leave_request lr
            JOIN leave_type lt ON lr.leave_type_id = lt.id
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            WHERE lr.user_id IN (${employeeIds.map(() => '?').join(',')})
            GROUP BY lr.user_id, lt.type
        `;
        
        const ytdData = await new Promise((resolve, reject) => {
            db.query(ytdQuery, employeeIds, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Create YTD lookup map
        const ytdMap = {};
        ytdData.forEach(ytd => {
            if (!ytdMap[ytd.employee_id]) {
                ytdMap[ytd.employee_id] = {};
            }
            ytdMap[ytd.employee_id][ytd.leave_type] = ytd.total_taken_ytd;
        });
        
        // Create Excel workbook
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Team Leave Requests');
        
        // Define headers
        const headers = [
            'Employee Name',
            'Leave Type', 
            'Reason',
            'Current Balance',
            'Total Taken (YTD)',
            'Start Date',
            'End Date',
            'Days Requested',
            'Request Date',
            'Status',
            'Manager Comments'
        ];
        
        // Add headers with formatting
        const headerRow = worksheet.addRow(headers);
        headerRow.font = { bold: true };
        headerRow.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE0E0E0' }
        };
        
        // Add data rows
        leaveRequests.forEach(request => {
            const balance = balanceMap[request.employee_id] || {};
            const ytd = ytdMap[request.employee_id] || {};
            
            // Get appropriate balance based on leave type
            let currentBalance = 0;
            let totalTakenYtd = 0;
            
            switch (request.leave_type) {
                case 'annual leave':
                    currentBalance = balance.annual_leave_balance || 0;
                    totalTakenYtd = ytd['annual leave'] || 0;
                    break;
                case 'medical leave':
                    currentBalance = balance.medical_leave_balance || 0;
                    totalTakenYtd = ytd['medical leave'] || 0;
                    break;
                case 'other leave':
                    currentBalance = balance.other_leave_balance || 0;
                    totalTakenYtd = ytd['other leave'] || 0;
                    break;
            }
            
            // Format dates
            const startDate = new Date(request.start_date).toLocaleDateString('en-GB');
            const endDate = new Date(request.end_date).toLocaleDateString('en-GB');
            const requestDate = new Date(request.request_date).toLocaleDateString('en-GB');
            
            // Determine status display
            let statusDisplay = 'Pending';
            if (request.approval_status === 'approved') {
                statusDisplay = 'Approved';
            } else if (request.approval_status === 'rejected') {
                statusDisplay = 'Rejected';
            }
            
            // Format employee display name without email
            const employeeDisplay = request.employee_name || request.employee_email;

            const row = worksheet.addRow([
                employeeDisplay,
                request.leave_type,
                request.reason,
                currentBalance,
                totalTakenYtd,
                startDate,
                endDate,
                request.number_of_days,
                requestDate,
                statusDisplay,
                request.manager_comment || ''
            ]);
            
            // Apply status-based row coloring
            if (request.approval_status === 'approved') {
                row.fill = {
                    type: 'pattern',
                    pattern: 'solid',
                    fgColor: { argb: 'FFE6F3E6' } // Light green
                };
            } else if (request.approval_status === 'rejected') {
                row.fill = {
                    type: 'pattern',
                    pattern: 'solid',
                    fgColor: { argb: 'FFFFE6E6' } // Light red
                };
            } else {
                row.fill = {
                    type: 'pattern',
                    pattern: 'solid',
                    fgColor: { argb: 'FFFFF5E6' } // Light yellow for pending
                };
            }
        });
        
        // Auto-fit columns
        worksheet.columns.forEach(column => {
            let maxLength = 0;
            column.eachCell({ includeEmpty: true }, (cell) => {
                const columnLength = cell.value ? cell.value.toString().length : 10;
                if (columnLength > maxLength) {
                    maxLength = columnLength;
                }
            });
            column.width = Math.min(Math.max(maxLength + 2, 10), 50);
        });
        
        // Add borders to all cells
        worksheet.eachRow({ includeEmpty: true }, (row) => {
            row.eachCell({ includeEmpty: true }, (cell) => {
                cell.border = {
                    top: { style: 'thin' },
                    left: { style: 'thin' },
                    bottom: { style: 'thin' },
                    right: { style: 'thin' }
                };
            });
        });
        
        // Freeze first row
        worksheet.views = [{ state: 'frozen', ySplit: 1 }];
        
        // Generate filename with current date
        const currentDate = new Date();
        const dateStr = currentDate.toISOString().slice(0, 10).replace(/-/g, '_');
        const timeStr = currentDate.toTimeString().slice(0, 5).replace(':', '_');
        const filename = `team_leave_requests_${dateStr}_${timeStr}.xlsx`;
        
        // Set response headers
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        
        // Write workbook to response
        await workbook.xlsx.write(res);
        res.end();
        
        console.log(`Excel export completed for manager ID: ${manager_id}, Records: ${leaveRequests.length}`);
        
    } catch (error) {
        console.error('Error generating Excel export:', error);
        res.status(500).json({
            success: false,
            message: 'Error generating Excel export'
        });
    }
});

// GET /manager/pending-count - Get count of pending leave requests for the manager
app.get('/manager/pending-count', authenticateUser, authorizeRole(['manager', 'admin']), (req, res) => {
    const manager_id = req.authenticatedUserId;
    
    // Query to count pending leave requests from direct reports
    const query = `
        SELECT COUNT(*) as pending_count
        FROM leave_request lr
        JOIN users u ON lr.user_id = u.id
        LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
        WHERE u.manager_id = ? 
        AND (lra.status IS NULL OR lra.status = '')
    `;
    
    db.query(query, [manager_id], (err, results) => {
        if (err) {
            console.error('Error fetching pending count for manager:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching pending approvals count'
            });
        }
        
        const pendingCount = results[0]?.pending_count || 0;
        
        res.json({
            success: true,
            data: {
                manager_id: parseInt(manager_id),
                pending_count: pendingCount
            }
        });
    });
});

// GET /manager/team-count - Get count of team members (direct reports)
app.get('/manager/team-count', authenticateUser, authorizeRole(['manager', 'admin']), (req, res) => {
    const manager_id = req.authenticatedUserId;
    
    // Query to count team members (direct reports)
    const query = `
        SELECT COUNT(*) as team_count
        FROM users 
        WHERE manager_id = ? AND role = 'employee'
    `;
    
    db.query(query, [manager_id], (err, results) => {
        if (err) {
            console.error('Error fetching team count for manager:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching team members count'
            });
        }
        
        const teamCount = results[0]?.team_count || 0;
        
        res.json({
            success: true,
            data: {
                manager_id: parseInt(manager_id),
                team_count: teamCount
            }
        });
    });
});

// GET /manager/team-members - Get list of team members (direct reports) for dropdown
app.get('/manager/team-members', authenticateUser, authorizeRole(['manager', 'admin']), (req, res) => {
    const manager_id = req.authenticatedUserId;
    
    // Query to get team members (direct reports) with their names
    const query = `
        SELECT id, name, email
        FROM users 
        WHERE manager_id = ? AND role = 'employee'
        ORDER BY name, email
    `;
    
    db.query(query, [manager_id], (err, results) => {
        if (err) {
            console.error('Error fetching team members for manager:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching team members'
            });
        }
        
        res.json({
            success: true,
            data: {
                manager_id: parseInt(manager_id),
                team_members: results
            }
        });
    });
});

// POST /manager/approve-request/:request_id - Approve a leave request
app.post('/manager/approve-request/:request_id', authenticateUser, authorizeRole(['manager', 'admin']), validateManagerAccess, (req, res) => {
    const { request_id } = req.params;
    const { comment } = req.body;
    const manager_id = req.authenticatedUserId;
    
    // Validate request_id parameter
    if (!request_id || isNaN(request_id)) {
        return res.status(400).json({
            success: false,
            message: 'Valid request ID is required'
        });
    }
    
    // Optional comment validation (can be empty for approvals)
    const approvalComment = comment ? comment.trim() : 'Approved by manager';
    
    if (approvalComment.length > 500) {
        return res.status(400).json({
            success: false,
            message: 'Comment cannot exceed 500 characters'
        });
    }
    
    // Start database transaction
    db.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start error:', err);
            return res.status(500).json({
                success: false,
                message: 'Database error occurred'
            });
        }
        
        // First, get the leave request details for validation and balance calculation
        const getRequestQuery = `
            SELECT 
                lr.id,
                lr.user_id,
                lr.leave_type_id,
                lr.start_date,
                lr.end_date,
                lr.number_of_days,
                lr.reason,
                u.email as employee_email,
                lt.type as leave_type,
                lra.status as current_status
            FROM leave_request lr
            JOIN users u ON lr.user_id = u.id
            JOIN leave_type lt ON lr.leave_type_id = lt.id
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            WHERE lr.id = ? AND u.manager_id = ?
        `;
        
        db.query(getRequestQuery, [request_id, manager_id], (err, requestResult) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Error fetching request details:', err);
                    res.status(500).json({
                        success: false,
                        message: 'Error fetching request details'
                    });
                });
            }
            
            if (requestResult.length === 0) {
                return db.rollback(() => {
                    res.status(404).json({
                        success: false,
                        message: 'Leave request not found or you do not have permission to approve it'
                    });
                });
            }
            
            const request = requestResult[0];
            
            // Check if request is already processed
            if (request.current_status === 'approved') {
                return db.rollback(() => {
                    res.status(400).json({
                        success: false,
                        message: 'Leave request has already been approved'
                    });
                });
            }
            
            if (request.current_status === 'rejected') {
                return db.rollback(() => {
                    res.status(400).json({
                        success: false,
                        message: 'Cannot approve a rejected leave request'
                    });
                });
            }
            
            // Check if the leave dates are still valid (not in the past)
            // Allow backdating for medical leave (leave_type_id = 2), but not for other leave types
            const today = new Date();
            const startDate = new Date(request.start_date);
            today.setHours(0, 0, 0, 0);
            
            if (startDate < today && parseInt(request.leave_type_id) !== 2) {
                return db.rollback(() => {
                    res.status(400).json({
                        success: false,
                        message: 'Cannot approve leave request for past dates'
                    });
                });
            }
            
            // Get leave balance field based on leave type
            const balanceField = getLeaveBalanceField(request.leave_type_id);
            if (!balanceField) {
                return db.rollback(() => {
                    res.status(500).json({
                        success: false,
                        message: 'Invalid leave type for balance calculation'
                    });
                });
            }
            
            // Check if employee has sufficient leave balance
            const balanceCheckQuery = `
                SELECT ${balanceField} as available_balance
                FROM leave_balance 
                WHERE user_id = ?
            `;
            
            db.query(balanceCheckQuery, [request.user_id], (err, balanceResult) => {
                if (err) {
                    return db.rollback(() => {
                        console.error('Error checking leave balance:', err);
                        res.status(500).json({
                            success: false,
                            message: 'Error checking employee leave balance'
                        });
                    });
                }
                
                if (balanceResult.length === 0) {
                    return db.rollback(() => {
                        res.status(404).json({
                            success: false,
                            message: 'Employee leave balance not found'
                        });
                    });
                }
                
                const availableBalance = parseFloat(balanceResult[0].available_balance);
                const requestedDays = parseFloat(request.number_of_days);
                
                if (availableBalance < requestedDays) {
                    return db.rollback(() => {
                        res.status(400).json({
                            success: false,
                            message: `Insufficient leave balance. Available: ${availableBalance} days, Requested: ${requestedDays} days`
                        });
                    });
                }
                
                // Update approval status
                const approvalQuery = `
                    INSERT INTO leave_request_approval (leave_request_id, status, comment) 
                    VALUES (?, 'approved', ?) 
                    ON DUPLICATE KEY UPDATE status = 'approved', comment = ?
                `;
                
                db.query(approvalQuery, [request_id, approvalComment, approvalComment], (err) => {
                    if (err) {
                        return db.rollback(() => {
                            console.error('Error updating approval status:', err);
                            res.status(500).json({
                                success: false,
                                message: 'Error updating approval status'
                            });
                        });
                    }
                    
                    // Deduct leave balance
                    const balanceUpdateQuery = `
                        UPDATE leave_balance 
                        SET ${balanceField} = ${balanceField} - ? 
                        WHERE user_id = ?
                    `;
                    
                    db.query(balanceUpdateQuery, [requestedDays, request.user_id], (err) => {
                        if (err) {
                            return db.rollback(() => {
                                console.error('Error updating leave balance:', err);
                                res.status(500).json({
                                    success: false,
                                    message: 'Error deducting leave balance'
                                });
                            });
                        }
                        
                        // Commit the transaction
                        db.commit((err) => {
                            if (err) {
                                return db.rollback(() => {
                                    console.error('Commit error:', err);
                                    res.status(500).json({
                                        success: false,
                                        message: 'Error finalizing approval'
                                    });
                                });
                            }
                            
                            // Success response
                            res.json({
                                success: true,
                                message: 'Leave request approved successfully',
                                data: {
                                    request_id: parseInt(request_id),
                                    employee_email: request.employee_email,
                                    leave_type: request.leave_type,
                                    start_date: request.start_date,
                                    end_date: request.end_date,
                                    number_of_days: requestedDays,
                                    approval_status: 'approved',
                                    approval_comment: approvalComment,
                                    approved_by: req.authenticatedUserEmail,
                                    balance_deducted: requestedDays,
                                    remaining_balance: availableBalance - requestedDays
                                }
                            });
                        });
                    });
                });
            });
        });
    });
});

// POST /manager/reject-request/:request_id - Reject a leave request
app.post('/manager/reject-request/:request_id', authenticateUser, authorizeRole(['manager', 'admin']), validateManagerAccess, (req, res) => {
    const { request_id } = req.params;
    const { comment } = req.body;
    const manager_id = req.authenticatedUserId;
    
    // Validate request_id parameter
    if (!request_id || isNaN(request_id)) {
        return res.status(400).json({
            success: false,
            message: 'Valid request ID is required'
        });
    }
    
    // Validate mandatory rejection comment
    if (!comment || !comment.trim()) {
        return res.status(400).json({
            success: false,
            message: 'Rejection comment is required'
        });
    }
    
    const rejectionComment = comment.trim();
    
    // Validate comment length
    if (rejectionComment.length < 5) {
        return res.status(400).json({
            success: false,
            message: 'Rejection comment must be at least 5 characters long'
        });
    }
    
    if (rejectionComment.length > 500) {
        return res.status(400).json({
            success: false,
            message: 'Rejection comment cannot exceed 500 characters'
        });
    }
    
    // Start database transaction
    db.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start error:', err);
            return res.status(500).json({
                success: false,
                message: 'Database error occurred'
            });
        }
        
        // First, get the leave request details for validation
        const getRequestQuery = `
            SELECT 
                lr.id,
                lr.user_id,
                lr.leave_type_id,
                lr.start_date,
                lr.end_date,
                lr.number_of_days,
                lr.reason,
                u.email as employee_email,
                lt.type as leave_type,
                lra.status as current_status
            FROM leave_request lr
            JOIN users u ON lr.user_id = u.id
            JOIN leave_type lt ON lr.leave_type_id = lt.id
            LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
            WHERE lr.id = ? AND u.manager_id = ?
        `;
        
        db.query(getRequestQuery, [request_id, manager_id], (err, requestResult) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Error fetching request details:', err);
                    res.status(500).json({
                        success: false,
                        message: 'Error fetching request details'
                    });
                });
            }
            
            if (requestResult.length === 0) {
                return db.rollback(() => {
                    res.status(404).json({
                        success: false,
                        message: 'Leave request not found or you do not have permission to reject it'
                    });
                });
            }
            
            const request = requestResult[0];
            
            // Check if request is already processed
            if (request.current_status === 'rejected') {
                return db.rollback(() => {
                    res.status(400).json({
                        success: false,
                        message: 'Leave request has already been rejected'
                    });
                });
            }
            
            if (request.current_status === 'approved') {
                return db.rollback(() => {
                    res.status(400).json({
                        success: false,
                        message: 'Cannot reject an approved leave request. Please contact HR for approved request changes.'
                    });
                });
            }
            
            // Update rejection status
            const rejectionQuery = `
                INSERT INTO leave_request_approval (leave_request_id, status, comment) 
                VALUES (?, 'rejected', ?) 
                ON DUPLICATE KEY UPDATE status = 'rejected', comment = ?
            `;
            
            db.query(rejectionQuery, [request_id, rejectionComment, rejectionComment], (err) => {
                if (err) {
                    return db.rollback(() => {
                        console.error('Error updating rejection status:', err);
                        res.status(500).json({
                            success: false,
                            message: 'Error updating rejection status'
                        });
                    });
                }
                
                // Commit the transaction
                db.commit((err) => {
                    if (err) {
                        return db.rollback(() => {
                            console.error('Commit error:', err);
                            res.status(500).json({
                                success: false,
                                message: 'Error finalizing rejection'
                            });
                        });
                    }
                    
                    // Success response
                    res.json({
                        success: true,
                        message: 'Leave request rejected successfully',
                        data: {
                            request_id: parseInt(request_id),
                            employee_email: request.employee_email,
                            leave_type: request.leave_type,
                            start_date: request.start_date,
                            end_date: request.end_date,
                            number_of_days: parseFloat(request.number_of_days),
                            approval_status: 'rejected',
                            rejection_comment: rejectionComment,
                            rejected_by: req.authenticatedUserEmail,
                            rejection_date: new Date().toISOString().split('T')[0]
                        }
                    });
                });
            });
        });
    });
});

// GET /manager/export-team-requests - Export leave requests to Excel
app.get('/manager/export-team-requests', authenticateUser, authorizeRole(['manager', 'admin']), async (req, res) => {
    const manager_id = req.authenticatedUserId;
    const { 
        format = 'excel',
        status, 
        employee_id, 
        leave_type, 
        start_date, 
        end_date
    } = req.query;
    
    try {
        // Validate format parameter
        if (format !== 'excel') {
            return res.status(400).json({
                success: false,
                message: 'Only Excel format is currently supported'
            });
        }
        
        // Build WHERE clause dynamically
        let whereClause = 'WHERE u.manager_id = ?';
        let queryParams = [manager_id];
        
        // Status filter
        if (status && status.trim() !== '') {
            if (status === 'pending') {
                whereClause += ' AND (lra.status IS NULL OR lra.status = "")';
            } else if (status === 'approved' || status === 'rejected') {
                whereClause += ' AND lra.status = ?';
                queryParams.push(status);
            }
        }
        
        // Employee filter
        if (employee_id && !isNaN(employee_id)) {
            whereClause += ' AND u.id = ?';
            queryParams.push(parseInt(employee_id));
        }
        
        // Leave type filter
        if (leave_type && leave_type.trim() !== '') {
            whereClause += ' AND lt.type = ?';
            queryParams.push(leave_type.trim());
        }
        
        // Date range filter
        if (start_date && end_date) {
            const startDateObj = new Date(start_date);
            const endDateObj = new Date(end_date);
            
            if (isNaN(startDateObj.getTime()) || isNaN(endDateObj.getTime())) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid date format. Use YYYY-MM-DD format.'
                });
            }
            
            if (startDateObj > endDateObj) {
                return res.status(400).json({
                    success: false,
                    message: 'Start date cannot be after end date.'
                });
            }
            
            whereClause += ' AND lr.start_date >= ? AND lr.end_date <= ?';
            queryParams.push(start_date, end_date);
        } else if (start_date) {
            const startDateObj = new Date(start_date);
            if (isNaN(startDateObj.getTime())) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid start_date format. Use YYYY-MM-DD format.'
                });
            }
            whereClause += ' AND lr.start_date >= ?';
            queryParams.push(start_date);
        } else if (end_date) {
            const endDateObj = new Date(end_date);
            if (isNaN(endDateObj.getTime())) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid end_date format. Use YYYY-MM-DD format.'
                });
            }
            whereClause += ' AND lr.end_date <= ?';
            queryParams.push(end_date);
        }
        
        // Execute queries in parallel using promises
        const getMainData = () => {
            return new Promise((resolve, reject) => {
                const mainQuery = `
                    SELECT 
                        u.id as employee_id,
                        u.name as employee_name,
                        u.email as employee_email,
                        lr.id as request_id,
                        lr.request_date,
                        lr.start_date,
                        lr.end_date,
                        lr.half_day,
                        lr.reason,
                        lr.number_of_days,
                        lt.type as leave_type,
                        lt.id as leave_type_id,
                        lra.status as approval_status,
                        lra.comment as manager_comment
                    FROM leave_request lr
                    JOIN users u ON lr.user_id = u.id
                    JOIN leave_type lt ON lr.leave_type_id = lt.id
                    LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
                    ${whereClause}
                    ORDER BY u.name ASC, lr.request_date DESC
                `;
                
                db.query(mainQuery, queryParams, (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        };
        
        const getLeaveBalances = () => {
            return new Promise((resolve, reject) => {
                const balanceQuery = `
                    SELECT 
                        u.id as employee_id,
                        u.name as employee_name,
                        lb.annual_leave_balance,
                        lb.medical_leave_balance,
                        lb.other_leave_balance,
                        lb.annual_leave_entitlement,
                        lb.medical_leave_entitlement,
                        lb.other_leave_entitlement
                    FROM users u
                    LEFT JOIN leave_balance lb ON u.id = lb.user_id
                    WHERE u.manager_id = ?
                `;
                
                db.query(balanceQuery, [manager_id], (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        };
        
        const getTotalTaken = () => {
            return new Promise((resolve, reject) => {
                const totalTakenQuery = `
                    SELECT 
                        u.id as employee_id,
                        lt.id as leave_type_id,
                        lt.type as leave_type,
                        COALESCE(SUM(
                            CASE 
                                WHEN lra.status = 'approved' 
                                AND YEAR(lr.start_date) = YEAR(CURDATE())
                                THEN lr.number_of_days 
                                ELSE 0 
                            END
                        ), 0) as total_taken_ytd
                    FROM users u
                    CROSS JOIN leave_type lt
                    LEFT JOIN leave_request lr ON u.id = lr.user_id AND lt.id = lr.leave_type_id
                    LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id
                    WHERE u.manager_id = ?
                    GROUP BY u.id, lt.id, lt.type
                    ORDER BY u.id, lt.id
                `;
                
                db.query(totalTakenQuery, [manager_id], (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        };
        
        // Execute all queries in parallel
        const [mainData, leaveBalances, totalTaken] = await Promise.all([
            getMainData(),
            getLeaveBalances(),
            getTotalTaken()
        ]);
        
        if (mainData.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'No leave requests found matching the specified criteria'
            });
        }
        
        // Create lookup objects for balances and totals
        const balanceLookup = {};
        leaveBalances.forEach(balance => {
            balanceLookup[balance.employee_id] = balance;
        });
        
        const totalTakenLookup = {};
        totalTaken.forEach(total => {
            if (!totalTakenLookup[total.employee_id]) {
                totalTakenLookup[total.employee_id] = {};
            }
            totalTakenLookup[total.employee_id][total.leave_type] = total.total_taken_ytd;
        });
        
        // Create Excel workbook
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Team Leave Requests');
        
        // Define headers
        const headers = [
            'Employee Name',
            'Leave Type', 
            'Reason',
            'Leave Entitlement',
            'Current Balance',
            'Total Taken (YTD)',
            'Start Date',
            'End Date',
            'Days Requested',
            'Status',
            'Manager Comments'
        ];
        
        // Add headers to worksheet
        worksheet.addRow(headers);
        
        // Style the header row
        const headerRow = worksheet.getRow(1);
        headerRow.font = { bold: true };
        headerRow.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE0E0E0' }
        };
        
        // Process and add data rows
        mainData.forEach(request => {
            const employeeBalance = balanceLookup[request.employee_id] || {};
            const employeeTaken = totalTakenLookup[request.employee_id] || {};
            
            // Get entitlement and balance based on leave type
            let entitlement = 'N/A';
            let currentBalance = 'N/A';
            let totalTakenYTD = employeeTaken[request.leave_type] || 0;
            
            switch (request.leave_type) {
                case 'annual leave':
                    entitlement = employeeBalance.annual_leave_entitlement ? parseFloat(employeeBalance.annual_leave_entitlement).toFixed(1) : 'N/A';
                    currentBalance = employeeBalance.annual_leave_balance || 0;
                    break;
                case 'medical leave':
                    entitlement = employeeBalance.medical_leave_entitlement ? parseFloat(employeeBalance.medical_leave_entitlement).toFixed(1) : 'N/A';
                    currentBalance = employeeBalance.medical_leave_balance || 0;
                    break;
                case 'other leave':
                    entitlement = employeeBalance.other_leave_entitlement ? parseFloat(employeeBalance.other_leave_entitlement).toFixed(1) : 'N/A';
                    currentBalance = employeeBalance.other_leave_balance || 0;
                    break;
            }
            
            // Format dates
            const formatDate = (date) => {
                if (!date) return 'N/A';
                return new Date(date).toLocaleDateString('en-GB'); // DD/MM/YYYY format
            };
            
            // Determine status with color coding info
            let status = request.approval_status || 'pending';
            status = status.charAt(0).toUpperCase() + status.slice(1);
            
            // Format employee display name without email
            const employeeDisplay = request.employee_name || request.employee_email;

            const row = [
                employeeDisplay,
                request.leave_type,
                request.reason || 'No reason provided',
                entitlement,
                parseFloat(currentBalance).toFixed(1),
                parseFloat(totalTakenYTD).toFixed(1),
                formatDate(request.start_date),
                formatDate(request.end_date),
                parseFloat(request.number_of_days).toFixed(1),
                status,
                request.manager_comment || ''
            ];
            
            const dataRow = worksheet.addRow(row);
            
            // Apply status color coding
            const statusCell = dataRow.getCell(10);
            switch (request.approval_status) {
                case 'approved':
                    statusCell.fill = {
                        type: 'pattern',
                        pattern: 'solid',
                        fgColor: { argb: 'FFD4EDDA' } // Light green
                    };
                    break;
                case 'rejected':
                    statusCell.fill = {
                        type: 'pattern',
                        pattern: 'solid',
                        fgColor: { argb: 'FFF8D7DA' } // Light red
                    };
                    break;
                default: // pending
                    statusCell.fill = {
                        type: 'pattern',
                        pattern: 'solid',
                        fgColor: { argb: 'FFFFF3CD' } // Light yellow
                    };
            }
        });
        
        // Auto-fit columns
        worksheet.columns.forEach(column => {
            let maxLength = 0;
            column.eachCell({ includeEmpty: true }, (cell) => {
                const cellLength = cell.value ? cell.value.toString().length : 10;
                if (cellLength > maxLength) {
                    maxLength = cellLength;
                }
            });
            column.width = Math.min(maxLength + 2, 30);
        });
        
        // Freeze first row
        worksheet.views = [{ state: 'frozen', ySplit: 1 }];
        
        // Add borders to all cells
        worksheet.eachRow((row, rowNumber) => {
            row.eachCell((cell) => {
                cell.border = {
                    top: { style: 'thin' },
                    left: { style: 'thin' },
                    bottom: { style: 'thin' },
                    right: { style: 'thin' }
                };
                
                // Align text
                if (rowNumber === 1) {
                    cell.alignment = { horizontal: 'center', vertical: 'middle' };
                } else {
                    // Numbers right-aligned, text left-aligned
                    const cellValue = cell.value;
                    if (typeof cellValue === 'number' || (typeof cellValue === 'string' && !isNaN(parseFloat(cellValue)))) {
                        cell.alignment = { horizontal: 'right', vertical: 'middle' };
                    } else {
                        cell.alignment = { horizontal: 'left', vertical: 'middle' };
                    }
                }
            });
        });
        
        // Generate filename with current date and time
        const now = new Date();
        const currentDate = now.toISOString().split('T')[0].replace(/-/g, '_');
        const currentTime = now.toTimeString().split(' ')[0].replace(/:/g, '_').slice(0, 5);
        const filename = `team_leave_requests_${currentDate}_${currentTime}.xlsx`;
        
        // Set response headers
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        
        // Generate and send the Excel file
        await workbook.xlsx.write(res);
        res.end();
        
        // Log export activity
        console.log(`Excel export generated by manager ${req.authenticatedUserEmail} (ID: ${manager_id}) at ${new Date().toISOString()}`);
        
    } catch (error) {
        console.error('Error generating Excel export:', error);
        
        // If headers already sent, we can't send JSON response
        if (res.headersSent) {
            return;
        }
        
        res.status(500).json({
            success: false,
            message: 'Error generating Excel export'
        });
    }
});

// POST /logout - Destroy session and redirect to login
app.post('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error logging out'
                });
            }
            
            // Clear the session cookie
            res.clearCookie('geolah_session');
            
            // For API requests, return JSON response
            if (req.headers.accept && req.headers.accept.includes('application/json')) {
                return res.json({
                    success: true,
                    message: 'Logged out successfully'
                });
            }
            
            // For web requests, redirect to login page
            res.redirect('/');
        });
    } else {
        // No session to destroy, just redirect
        res.redirect('/');
    }
});

// Temporary function to hash a password
async function hashPasswordForUser(plainPassword) {
    try {
        const hashed = await hashPassword(plainPassword);
        console.log('Plain password:', plainPassword);
        console.log('Hashed password:', hashed);
        return hashed;
    } catch (error) {
        console.error('Error:', error);
    }
}

// ===== ADMIN ENDPOINTS =====




// GET /admin/users - List all users with manager names and leave balances
app.get('/admin/users', authenticateUser, authorizeRole(['admin']), (req, res) => {
    try {
        // Extract query parameters for filtering
        const roleFilter = req.query.role; // admin, manager, employee
        const statusFilter = req.query.status; // active, inactive 
        const searchQuery = req.query.search; // search by email
        
        // Debug: Log received parameters
        console.log('GET /admin/users - Query parameters:', {
            role: roleFilter,
            status: statusFilter,
            search: searchQuery,
            rawQuery: req.query
        });
        
        // Base SQL query with JOINs to get manager names and leave balances
        let sql = `
            SELECT 
                u.id,
                u.name,
                u.email,
                u.role,
                u.manager_id,
                COALESCE(u.active, 1) as active,
                manager.name as manager_name,
                manager.email as manager_email,
                lb.annual_leave_balance,
                lb.medical_leave_balance,
                lb.other_leave_balance
            FROM users u
            LEFT JOIN users manager ON u.manager_id = manager.id
            LEFT JOIN leave_balance lb ON u.id = lb.user_id
        `;
        
        // Build WHERE conditions
        let whereConditions = [];
        let queryParams = [];
        
        // Role filter
        if (roleFilter && ['admin', 'manager', 'employee'].includes(roleFilter)) {
            whereConditions.push('u.role = ?');
            queryParams.push(roleFilter);
        }
        
        // Status filter (active/inactive)
        if (statusFilter && ['active', 'inactive'].includes(statusFilter)) {
            if (statusFilter === 'active') {
                whereConditions.push('(u.active = 1 OR u.active IS NULL)');
            } else {
                whereConditions.push('u.active = 0');
            }
        }
        
        // Search filter (by name or email)
        if (searchQuery && searchQuery.trim()) {
            whereConditions.push('(u.name LIKE ? OR u.email LIKE ?)');
            queryParams.push(`%${searchQuery.trim()}%`);
            queryParams.push(`%${searchQuery.trim()}%`);
        }
        
        // Add WHERE clause if conditions exist
        if (whereConditions.length > 0) {
            sql += ' WHERE ' + whereConditions.join(' AND ');
        }
        
        // Order by role (admin first, then manager, then employee) and email
        sql += ' ORDER BY FIELD(u.role, "admin", "manager", "employee"), u.email ASC';
        
        // Debug: Log the final SQL query and parameters
        console.log('Final SQL query:', sql);
        console.log('Query parameters:', queryParams);
        
        // Execute query
        db.query(sql, queryParams, (err, results) => {
            if (err) {
                console.error('Database error fetching users:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Database error occurred while fetching users',
                    error: process.env.NODE_ENV === 'development' ? err.message : undefined
                });
            }
            
            // Transform results to include computed fields and clean data
            const users = results.map(user => ({
                id: user.id,
                name: user.name || '',
                email: user.email,
                role: user.role,
                manager_id: user.manager_id,
                manager_name: user.manager_name || null,
                manager_email: user.manager_email || null,
                active: user.active === 1 || user.active === null,
                status: (user.active === 1 || user.active === null) ? 'active' : 'inactive',
                leave_balances: {
                    annual: parseFloat(user.annual_leave_balance) || 0,
                    medical: parseFloat(user.medical_leave_balance) || 0,
                    other: parseFloat(user.other_leave_balance) || 0
                }
            }));
            
            // Log successful admin action
            console.log(`Admin ${req.authenticatedUserId} (${req.authenticatedUserEmail}) viewed users list. Filter: role=${roleFilter || 'all'}, search='${searchQuery || ''}'`);
            
            res.json({
                success: true,
                data: users,
                count: users.length,
                filters: {
                    role: roleFilter || null,
                    status: statusFilter || null,
                    search: searchQuery || null
                },
                message: `Retrieved ${users.length} user(s) successfully`
            });
        });
        
    } catch (error) {
        console.error('Error in GET /admin/users:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// POST /admin/users - Create new user with name field
app.post('/admin/users', authenticateUser, authorizeRole(['admin']), async (req, res) => {
    // Start database transaction
    const transaction = await new Promise((resolve, reject) => {
        db.beginTransaction((err) => {
            if (err) reject(err);
            else resolve();
        });
    }).catch(err => {
        console.error('Error starting transaction:', err);
        return res.status(500).json({
            success: false,
            message: 'Database transaction error'
        });
    });

    try {
        const { name, email, password, role, manager_id, annual_leave_balance, medical_leave_balance, other_leave_balance } = req.body;
        
        // ===== INPUT VALIDATION =====
        
        // Required fields validation
        if (!name || !email || !password || !role) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: name, email, password, and role are required'
            });
        }
        
        // Name validation (2-100 characters, letters, spaces, hyphens, apostrophes)
        if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
            return res.status(400).json({
                success: false,
                message: 'Name must be between 2 and 100 characters'
            });
        }
        
        if (!/^[a-zA-Z\s\-']+$/.test(name.trim())) {
            return res.status(400).json({
                success: false,
                message: 'Name can only contain letters, spaces, hyphens, and apostrophes'
            });
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email) || email.length > 254) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }
        
        // Password validation (minimum 8 characters)
        if (typeof password !== 'string' || password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }
        
        // Role validation
        if (!['admin', 'manager', 'employee'].includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Role must be admin, manager, or employee'
            });
        }
        
        // Manager ID validation (required for employees and managers)
        if (role !== 'admin' && (!manager_id || isNaN(parseInt(manager_id)))) {
            return res.status(400).json({
                success: false,
                message: 'Manager ID is required for employees and managers'
            });
        }
        
        // Leave balances validation (optional, defaults provided)
        const annualBalance = parseFloat(annual_leave_balance) || 10.00;
        const medicalBalance = parseFloat(medical_leave_balance) || 14.00;
        const otherBalance = parseFloat(other_leave_balance) || 5.00;
        
        if (annualBalance < 0 || annualBalance > 365 || 
            medicalBalance < 0 || medicalBalance > 365 || 
            otherBalance < 0 || otherBalance > 365) {
            return res.status(400).json({
                success: false,
                message: 'Leave balances must be between 0 and 365 days'
            });
        }
        
        // ===== DATABASE VALIDATIONS =====
        
        // Check email uniqueness
        const emailCheckResult = await new Promise((resolve, reject) => {
            db.query('SELECT id FROM users WHERE email = ?', [email], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        if (emailCheckResult.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Email address already exists'
            });
        }
        
        // Validate manager exists and has appropriate role (if specified)
        if (role !== 'admin' && manager_id) {
            const managerCheckResult = await new Promise((resolve, reject) => {
                db.query(
                    'SELECT id, role FROM users WHERE id = ?', 
                    [manager_id], 
                    (err, results) => {
                        if (err) reject(err);
                        else resolve(results);
                    }
                );
            });
            
            if (managerCheckResult.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Specified manager does not exist'
                });
            }
            
            if (!['manager', 'admin'].includes(managerCheckResult[0].role)) {
                return res.status(400).json({
                    success: false,
                    message: 'Specified manager must have manager or admin role'
                });
            }
        }
        
        // ===== CREATE USER =====
        
        // Hash password
        const hashedPassword = await hashPassword(password);
        
        // Insert user record
        const userInsertResult = await new Promise((resolve, reject) => {
            const userSql = 'INSERT INTO users (name, email, password, role, manager_id) VALUES (?, ?, ?, ?, ?)';
            const userParams = [name.trim(), email.toLowerCase(), hashedPassword, role, role === 'admin' ? null : manager_id];
            
            db.query(userSql, userParams, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        const newUserId = userInsertResult.insertId;
        
        // Insert leave balance record
        await new Promise((resolve, reject) => {
            const balanceSql = 'INSERT INTO leave_balance (user_id, annual_leave_balance, medical_leave_balance, other_leave_balance) VALUES (?, ?, ?, ?)';
            const balanceParams = [newUserId, annualBalance, medicalBalance, otherBalance];
            
            db.query(balanceSql, balanceParams, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Commit transaction
        await new Promise((resolve, reject) => {
            db.commit((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        // Log successful admin action
        console.log(`Admin ${req.authenticatedUserId} (${req.authenticatedUserEmail}) created new user: ${email} (${role})`);
        
        // Return created user details (without password)
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: {
                id: newUserId,
                name: name.trim(),
                email: email.toLowerCase(),
                role: role,
                manager_id: role === 'admin' ? null : parseInt(manager_id),
                leave_balances: {
                    annual: annualBalance,
                    medical: medicalBalance,
                    other: otherBalance
                }
            }
        });
        
    } catch (error) {
        // Rollback transaction on error
        db.rollback(() => {
            console.error('Error creating user, transaction rolled back:', error);
        });
        
        res.status(500).json({
            success: false,
            message: 'Internal server error occurred while creating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// PUT /admin/users/:id - Update existing user with name field
app.put('/admin/users/:id', authenticateUser, authorizeRole(['admin']), async (req, res) => {
    // Start database transaction
    const transaction = await new Promise((resolve, reject) => {
        db.beginTransaction((err) => {
            if (err) reject(err);
            else resolve();
        });
    }).catch(err => {
        console.error('Error starting transaction:', err);
        return res.status(500).json({
            success: false,
            message: 'Database transaction error'
        });
    });

    try {
        const userId = parseInt(req.params.id);
        const { name, email, password, role, manager_id, annual_leave_balance, medical_leave_balance, other_leave_balance } = req.body;
        
        // ===== BASIC VALIDATION =====
        
        // User ID validation
        if (isNaN(userId) || userId <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // Check if user exists
        const existingUserResult = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        if (existingUserResult.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const existingUser = existingUserResult[0];
        
        // Prevent admin from updating themselves to avoid lockout
        if (userId === req.authenticatedUserId && role && role !== 'admin') {
            return res.status(400).json({
                success: false,
                message: 'Cannot change your own admin role'
            });
        }
        
        // ===== INPUT VALIDATION (only validate provided fields) =====
        
        let updateFields = [];
        let updateParams = [];
        
        // Name validation (if provided)
        if (name !== undefined) {
            if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
                return res.status(400).json({
                    success: false,
                    message: 'Name must be between 2 and 100 characters'
                });
            }
            
            if (!/^[a-zA-Z\s\-']+$/.test(name.trim())) {
                return res.status(400).json({
                    success: false,
                    message: 'Name can only contain letters, spaces, hyphens, and apostrophes'
                });
            }
            
            updateFields.push('name = ?');
            updateParams.push(name.trim());
        }
        
        // Email validation (if provided)
        if (email !== undefined) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email) || email.length > 254) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid email format'
                });
            }
            
            // Check email uniqueness (exclude current user)
            const emailCheckResult = await new Promise((resolve, reject) => {
                db.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, userId], (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
            
            if (emailCheckResult.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Email address already exists'
                });
            }
            
            updateFields.push('email = ?');
            updateParams.push(email.toLowerCase());
        }
        
        // Password validation (if provided)
        let hashedPassword = null;
        if (password !== undefined) {
            if (typeof password !== 'string' || password.length < 8) {
                return res.status(400).json({
                    success: false,
                    message: 'Password must be at least 8 characters long'
                });
            }
            
            hashedPassword = await hashPassword(password);
            updateFields.push('password = ?');
            updateParams.push(hashedPassword);
        }
        
        // Role validation (if provided)
        if (role !== undefined) {
            if (!['admin', 'manager', 'employee'].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: 'Role must be admin, manager, or employee'
                });
            }
            
            // Prevent demoting the last admin
            if (existingUser.role === 'admin' && role !== 'admin') {
                const adminCountResult = await new Promise((resolve, reject) => {
                    db.query('SELECT COUNT(*) as count FROM users WHERE role = "admin"', (err, results) => {
                        if (err) reject(err);
                        else resolve(results);
                    });
                });
                
                if (adminCountResult[0].count <= 1) {
                    return res.status(400).json({
                        success: false,
                        message: 'Cannot demote the last admin user'
                    });
                }
            }
            
            updateFields.push('role = ?');
            updateParams.push(role);
        }
        
        // Manager ID validation (if provided)
        if (manager_id !== undefined) {
            const newRole = role || existingUser.role;
            
            if (newRole !== 'admin') {
                if (!manager_id || isNaN(parseInt(manager_id))) {
                    return res.status(400).json({
                        success: false,
                        message: 'Manager ID is required for employees and managers'
                    });
                }
                
                // Prevent user from being their own manager
                if (parseInt(manager_id) === userId) {
                    return res.status(400).json({
                        success: false,
                        message: 'User cannot be their own manager'
                    });
                }
                
                // Validate manager exists and has appropriate role
                const managerCheckResult = await new Promise((resolve, reject) => {
                    db.query(
                        'SELECT id, role FROM users WHERE id = ?', 
                        [manager_id], 
                        (err, results) => {
                            if (err) reject(err);
                            else resolve(results);
                        }
                    );
                });
                
                if (managerCheckResult.length === 0) {
                    return res.status(400).json({
                        success: false,
                        message: 'Specified manager does not exist'
                    });
                }
                
                if (!['manager', 'admin'].includes(managerCheckResult[0].role)) {
                    return res.status(400).json({
                        success: false,
                        message: 'Specified manager must have manager or admin role'
                    });
                }
                
                updateFields.push('manager_id = ?');
                updateParams.push(parseInt(manager_id));
            } else {
                // Admin users don't have managers
                updateFields.push('manager_id = ?');
                updateParams.push(null);
            }
        }
        
        // ===== UPDATE USER RECORD =====
        
        if (updateFields.length > 0) {
            updateParams.push(userId);
            const userUpdateSql = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
            
            await new Promise((resolve, reject) => {
                db.query(userUpdateSql, updateParams, (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        }
        
        // ===== UPDATE LEAVE BALANCES =====
        
        let balanceUpdateFields = [];
        let balanceUpdateParams = [];
        
        // Validate and update leave balances (if provided)
        if (annual_leave_balance !== undefined) {
            const annualBalance = parseFloat(annual_leave_balance);
            if (isNaN(annualBalance) || annualBalance < 0 || annualBalance > 365) {
                return res.status(400).json({
                    success: false,
                    message: 'Annual leave balance must be between 0 and 365 days'
                });
            }
            balanceUpdateFields.push('annual_leave_balance = ?');
            balanceUpdateParams.push(annualBalance);
        }
        
        if (medical_leave_balance !== undefined) {
            const medicalBalance = parseFloat(medical_leave_balance);
            if (isNaN(medicalBalance) || medicalBalance < 0 || medicalBalance > 365) {
                return res.status(400).json({
                    success: false,
                    message: 'Medical leave balance must be between 0 and 365 days'
                });
            }
            balanceUpdateFields.push('medical_leave_balance = ?');
            balanceUpdateParams.push(medicalBalance);
        }
        
        if (other_leave_balance !== undefined) {
            const otherBalance = parseFloat(other_leave_balance);
            if (isNaN(otherBalance) || otherBalance < 0 || otherBalance > 365) {
                return res.status(400).json({
                    success: false,
                    message: 'Other leave balance must be between 0 and 365 days'
                });
            }
            balanceUpdateFields.push('other_leave_balance = ?');
            balanceUpdateParams.push(otherBalance);
        }
        
        if (balanceUpdateFields.length > 0) {
            balanceUpdateParams.push(userId);
            const balanceUpdateSql = `UPDATE leave_balance SET ${balanceUpdateFields.join(', ')} WHERE user_id = ?`;
            
            await new Promise((resolve, reject) => {
                db.query(balanceUpdateSql, balanceUpdateParams, (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        }
        
        // ===== GET UPDATED USER DATA =====
        
        const updatedUserResult = await new Promise((resolve, reject) => {
            const sql = `
                SELECT 
                    u.id,
                    u.name,
                    u.email,
                    u.role,
                    u.manager_id,
                    manager.name as manager_name,
                    manager.email as manager_email,
                    lb.annual_leave_balance,
                    lb.medical_leave_balance,
                    lb.other_leave_balance
                FROM users u
                LEFT JOIN users manager ON u.manager_id = manager.id
                LEFT JOIN leave_balance lb ON u.id = lb.user_id
                WHERE u.id = ?
            `;
            
            db.query(sql, [userId], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        // Commit transaction
        await new Promise((resolve, reject) => {
            db.commit((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        const updatedUser = updatedUserResult[0];
        
        // Log successful admin action
        console.log(`Admin ${req.authenticatedUserId} (${req.authenticatedUserEmail}) updated user ${userId}: ${updatedUser.email}`);
        
        // Return updated user details (without password)
        res.json({
            success: true,
            message: 'User updated successfully',
            data: {
                id: updatedUser.id,
                name: updatedUser.name || '',
                email: updatedUser.email,
                role: updatedUser.role,
                manager_id: updatedUser.manager_id,
                manager_name: updatedUser.manager_name || null,
                manager_email: updatedUser.manager_email || null,
                leave_balances: {
                    annual: parseFloat(updatedUser.annual_leave_balance) || 0,
                    medical: parseFloat(updatedUser.medical_leave_balance) || 0,
                    other: parseFloat(updatedUser.other_leave_balance) || 0
                }
            }
        });
        
    } catch (error) {
        // Rollback transaction on error
        db.rollback(() => {
            console.error('Error updating user, transaction rolled back:', error);
        });
        
        res.status(500).json({
            success: false,
            message: 'Internal server error occurred while updating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// DELETE /admin/users/:id - Deactivate user (soft delete)
app.delete('/admin/users/:id', authenticateUser, authorizeRole(['admin']), async (req, res) => {
    // Start database transaction
    const transaction = await new Promise((resolve, reject) => {
        db.beginTransaction((err) => {
            if (err) reject(err);
            else resolve();
        });
    }).catch(err => {
        console.error('Error starting transaction:', err);
        return res.status(500).json({
            success: false,
            message: 'Database transaction error'
        });
    });

    try {
        const userId = parseInt(req.params.id);
        
        // ===== BASIC VALIDATION =====
        
        // User ID validation
        if (isNaN(userId) || userId <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // Prevent admin from deactivating themselves
        if (userId === req.authenticatedUserId) {
            return res.status(400).json({
                success: false,
                message: 'Cannot deactivate your own account'
            });
        }
        
        // ===== CHECK USER EXISTS AND GET USER INFO =====
        
        const existingUserResult = await new Promise((resolve, reject) => {
            // First check if active column exists, if not we'll use a fallback approach
            db.query('DESCRIBE users', (err, results) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                const hasActiveColumn = results.some(column => column.Field === 'active');
                
                let sql;
                if (hasActiveColumn) {
                    sql = 'SELECT id, name, email, role, active FROM users WHERE id = ?';
                } else {
                    sql = 'SELECT id, name, email, role, 1 as active FROM users WHERE id = ?';
                }
                
                db.query(sql, [userId], (err, results) => {
                    if (err) reject(err);
                    else resolve({ results, hasActiveColumn });
                });
            });
        });
        
        if (existingUserResult.results.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const existingUser = existingUserResult.results[0];
        const hasActiveColumn = existingUserResult.hasActiveColumn;
        
        // Check if user is already deactivated (if active column exists)
        if (hasActiveColumn && existingUser.active === 0) {
            return res.status(400).json({
                success: false,
                message: 'User is already deactivated'
            });
        }
        
        // ===== ADMIN PROTECTION =====
        
        // Prevent deactivating the last admin
        if (existingUser.role === 'admin') {
            const activeAdminCountResult = await new Promise((resolve, reject) => {
                let sql;
                if (hasActiveColumn) {
                    sql = 'SELECT COUNT(*) as count FROM users WHERE role = "admin" AND (active = 1 OR active IS NULL)';
                } else {
                    sql = 'SELECT COUNT(*) as count FROM users WHERE role = "admin"';
                }
                
                db.query(sql, (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
            
            if (activeAdminCountResult[0].count <= 1) {
                return res.status(400).json({
                    success: false,
                    message: 'Cannot deactivate the last admin user'
                });
            }
        }
        
        // ===== CHECK FOR PENDING LEAVE REQUESTS =====
        
        const pendingRequestsResult = await new Promise((resolve, reject) => {
            const sql = `
                SELECT COUNT(*) as count 
                FROM leave_request lr 
                LEFT JOIN leave_request_approval lra ON lr.id = lra.leave_request_id 
                WHERE lr.user_id = ? AND (lra.status IS NULL OR lra.status = '')
                AND lr.start_date > CURDATE()
            `;
            
            db.query(sql, [userId], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
        
        if (pendingRequestsResult[0].count > 0) {
            return res.status(400).json({
                success: false,
                message: `Cannot deactivate user with ${pendingRequestsResult[0].count} pending leave request(s). Please resolve pending requests first.`
            });
        }
        
        // ===== DEACTIVATE USER =====
        
        if (hasActiveColumn) {
            // Use soft delete with active column
            await new Promise((resolve, reject) => {
                db.query(
                    'UPDATE users SET active = 0 WHERE id = ?',
                    [userId],
                    (err, results) => {
                        if (err) reject(err);
                        else resolve(results);
                    }
                );
            });
        } else {
            // If no active column exists, we need to add it first
            await new Promise((resolve, reject) => {
                db.query(
                    'ALTER TABLE users ADD COLUMN active TINYINT(1) DEFAULT 1 AFTER manager_id',
                    (err, results) => {
                        if (err) {
                            // Column might already exist, ignore error and continue
                            console.log('Active column might already exist, continuing...');
                        }
                        resolve();
                    }
                );
            });
            
            // Now deactivate the user
            await new Promise((resolve, reject) => {
                db.query(
                    'UPDATE users SET active = 0 WHERE id = ?',
                    [userId],
                    (err, results) => {
                        if (err) reject(err);
                        else resolve(results);
                    }
                );
            });
        }
        
        // ===== UPDATE MANAGED EMPLOYEES =====
        
        // Find employees managed by this user and set their manager to null or reassign
        const managedEmployeesResult = await new Promise((resolve, reject) => {
            db.query(
                'SELECT id, name, email FROM users WHERE manager_id = ?',
                [userId],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                }
            );
        });
        
        if (managedEmployeesResult.length > 0) {
            // Set manager_id to null for all managed employees
            // In a real application, you might want to reassign to another manager
            await new Promise((resolve, reject) => {
                db.query(
                    'UPDATE users SET manager_id = NULL WHERE manager_id = ?',
                    [userId],
                    (err, results) => {
                        if (err) reject(err);
                        else resolve(results);
                    }
                );
            });
        }
        
        // Commit transaction
        await new Promise((resolve, reject) => {
            db.commit((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        // Log successful admin action
        console.log(`Admin ${req.authenticatedUserId} (${req.authenticatedUserEmail}) deactivated user ${userId}: ${existingUser.email} (${existingUser.role})`);
        
        if (managedEmployeesResult.length > 0) {
            console.log(`- Unassigned ${managedEmployeesResult.length} managed employee(s): ${managedEmployeesResult.map(emp => emp.email).join(', ')}`);
        }
        
        // Return success response
        res.json({
            success: true,
            message: 'User deactivated successfully',
            data: {
                deactivated_user: {
                    id: existingUser.id,
                    name: existingUser.name || '',
                    email: existingUser.email,
                    role: existingUser.role
                },
                managed_employees_affected: managedEmployeesResult.length,
                managed_employees: managedEmployeesResult.map(emp => ({
                    id: emp.id,
                    name: emp.name || '',
                    email: emp.email,
                    status: 'manager_unassigned'
                }))
            }
        });
        
    } catch (error) {
        // Rollback transaction on error
        db.rollback(() => {
            console.error('Error deactivating user, transaction rolled back:', error);
        });
        
        res.status(500).json({
            success: false,
            message: 'Internal server error occurred while deactivating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// PUT /admin/users/:id/activate - Reactivate user
app.put('/admin/users/:id/activate', authenticateUser, authorizeRole(['admin']), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        // ===== BASIC VALIDATION =====
        if (isNaN(userId) || userId <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // ===== CHECK USER EXISTS =====
        const existingUserResult = await new Promise((resolve, reject) => {
            db.query(
                'SELECT id, name, email, role, COALESCE(active, 1) as active FROM users WHERE id = ?', 
                [userId], 
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                }
            );
        });
        
        if (existingUserResult.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const existingUser = existingUserResult[0];
        
        // Check if user is already active
        if (existingUser.active === 1) {
            return res.status(400).json({
                success: false,
                message: 'User is already active'
            });
        }
        
        // ===== REACTIVATE USER =====
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE users SET active = 1 WHERE id = ?',
                [userId],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                }
            );
        });
        
        // Log successful admin action
        console.log(`Admin ${req.authenticatedUserId} (${req.authenticatedUserEmail}) reactivated user ${userId}: ${existingUser.email} (${existingUser.role})`);
        
        // Return success response
        res.json({
            success: true,
            message: 'User reactivated successfully',
            data: {
                reactivated_user: {
                    id: existingUser.id,
                    name: existingUser.name || '',
                    email: existingUser.email,
                    role: existingUser.role
                }
            }
        });
        
    } catch (error) {
        console.error('Error reactivating user:', error);
        
        res.status(500).json({
            success: false,
            message: 'Internal server error occurred while reactivating user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ===== ADMIN LEAVE TYPE MANAGEMENT ENDPOINTS =====

// GET /admin/leave-types - Retrieve all leave types
app.get('/admin/leave-types', authenticateUser, authorizeRole(['admin']), (req, res) => {
    const query = 'SELECT id, type FROM leave_type ORDER BY id';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching leave types:', err);
            return res.status(500).json({
                success: false,
                message: 'Error fetching leave types'
            });
        }

        res.json({
            success: true,
            data: results
        });
    });
});

// POST /admin/leave-types - Create new leave type
app.post('/admin/leave-types', authenticateUser, authorizeRole(['admin']), (req, res) => {
    const { type } = req.body;

    // Input validation
    if (!type || typeof type !== 'string') {
        return res.status(400).json({
            success: false,
            message: 'Leave type is required and must be a string'
        });
    }

    const trimmedType = type.trim();
    
    // Length validation
    if (trimmedType.length < 3 || trimmedType.length > 50) {
        return res.status(400).json({
            success: false,
            message: 'Leave type must be between 3 and 50 characters'
        });
    }

    // XSS prevention - check for suspicious characters
    const suspiciousChars = /<|>|&|"|'/;
    if (suspiciousChars.test(trimmedType)) {
        return res.status(400).json({
            success: false,
            message: 'Leave type contains invalid characters'
        });
    }

    // Check for duplicate leave types (case-insensitive)
    const duplicateQuery = 'SELECT id FROM leave_type WHERE LOWER(TRIM(type)) = LOWER(?)';
    
    db.query(duplicateQuery, [trimmedType], (err, duplicateResults) => {
        if (err) {
            console.error('Error checking for duplicate leave type:', err);
            return res.status(500).json({
                success: false,
                message: 'Error validating leave type'
            });
        }

        if (duplicateResults.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Leave type already exists'
            });
        }

        // Insert new leave type
        const insertQuery = 'INSERT INTO leave_type (type) VALUES (?)';
        
        db.query(insertQuery, [trimmedType], (err, insertResult) => {
            if (err) {
                console.error('Error creating leave type:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error creating leave type'
                });
            }

            res.status(201).json({
                success: true,
                message: 'Leave type created successfully',
                data: {
                    id: insertResult.insertId,
                    type: trimmedType
                }
            });
        });
    });
});

// PUT /admin/leave-types/:id - Update existing leave type
app.put('/admin/leave-types/:id', authenticateUser, authorizeRole(['admin']), (req, res) => {
    const leaveTypeId = parseInt(req.params.id);
    const { type } = req.body;

    // ID validation
    if (isNaN(leaveTypeId) || leaveTypeId <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Invalid leave type ID'
        });
    }

    // Input validation
    if (!type || typeof type !== 'string') {
        return res.status(400).json({
            success: false,
            message: 'Leave type is required and must be a string'
        });
    }

    const trimmedType = type.trim();
    
    // Length validation
    if (trimmedType.length < 3 || trimmedType.length > 50) {
        return res.status(400).json({
            success: false,
            message: 'Leave type must be between 3 and 50 characters'
        });
    }

    // XSS prevention
    const suspiciousChars = /<|>|&|"|'/;
    if (suspiciousChars.test(trimmedType)) {
        return res.status(400).json({
            success: false,
            message: 'Leave type contains invalid characters'
        });
    }

    // Check if leave type exists
    const existsQuery = 'SELECT id, type FROM leave_type WHERE id = ?';
    
    db.query(existsQuery, [leaveTypeId], (err, existsResults) => {
        if (err) {
            console.error('Error checking leave type existence:', err);
            return res.status(500).json({
                success: false,
                message: 'Error validating leave type'
            });
        }

        if (existsResults.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Leave type not found'
            });
        }

        // Check for duplicate names (excluding current record)
        const duplicateQuery = 'SELECT id FROM leave_type WHERE LOWER(TRIM(type)) = LOWER(?) AND id != ?';
        
        db.query(duplicateQuery, [trimmedType, leaveTypeId], (err, duplicateResults) => {
            if (err) {
                console.error('Error checking for duplicate leave type:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error validating leave type'
                });
            }

            if (duplicateResults.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Leave type already exists'
                });
            }

            // Update leave type
            const updateQuery = 'UPDATE leave_type SET type = ? WHERE id = ?';
            
            db.query(updateQuery, [trimmedType, leaveTypeId], (err, updateResult) => {
                if (err) {
                    console.error('Error updating leave type:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error updating leave type'
                    });
                }

                res.json({
                    success: true,
                    message: 'Leave type updated successfully',
                    data: {
                        id: leaveTypeId,
                        type: trimmedType
                    }
                });
            });
        });
    });
});

// DELETE /admin/leave-types/:id - Delete leave type
app.delete('/admin/leave-types/:id', authenticateUser, authorizeRole(['admin']), (req, res) => {
    const leaveTypeId = parseInt(req.params.id);

    // ID validation
    if (isNaN(leaveTypeId) || leaveTypeId <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Invalid leave type ID'
        });
    }

    // Check if leave type exists
    const existsQuery = 'SELECT id, type FROM leave_type WHERE id = ?';
    
    db.query(existsQuery, [leaveTypeId], (err, existsResults) => {
        if (err) {
            console.error('Error checking leave type existence:', err);
            return res.status(500).json({
                success: false,
                message: 'Error validating leave type'
            });
        }

        if (existsResults.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Leave type not found'
            });
        }

        const leaveTypeName = existsResults[0].type;

        // Check if leave type is referenced in leave_request table
        const referencesQuery = 'SELECT COUNT(*) as count FROM leave_request WHERE leave_type_id = ?';
        
        db.query(referencesQuery, [leaveTypeId], (err, referencesResults) => {
            if (err) {
                console.error('Error checking leave type references:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error validating leave type deletion'
                });
            }

            const referenceCount = referencesResults[0].count;
            
            if (referenceCount > 0) {
                return res.status(409).json({
                    success: false,
                    message: `Cannot delete leave type "${leaveTypeName}" because it is referenced by ${referenceCount} leave request(s)`
                });
            }

            // Delete leave type
            const deleteQuery = 'DELETE FROM leave_type WHERE id = ?';
            
            db.query(deleteQuery, [leaveTypeId], (err, deleteResult) => {
                if (err) {
                    console.error('Error deleting leave type:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error deleting leave type'
                    });
                }

                res.json({
                    success: true,
                    message: 'Leave type deleted successfully',
                    data: {
                        id: leaveTypeId,
                        type: leaveTypeName
                    }
                });
            });
        });
    });
});


// Uncomment and modify the line below to hash your password, then run the server
// hashPasswordForUser('your_password_here');

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});

