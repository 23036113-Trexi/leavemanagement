const express= require('express');
const mysql = require('mysql2');
const app = express();

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', './views');

// middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static('public'));

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

app.get('/', (req,res)=> {
    res.send("Hello world!")
})

// GET /leave-request-form - Serve the leave request form page
app.get('/leave-request-form', (req, res) => {
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

// GET /employee/leave-balance/:user_id - Get employee's leave balance
app.get('/employee/leave-balance/:user_id', (req, res) => {
    const { user_id } = req.params;
    
    // Validate user_id parameter
    if (!user_id || isNaN(user_id)) {
        return res.status(400).json({
            success: false,
            message: 'Valid user ID is required'
        });
    }
    
    // Query to get leave balance for the user
    const query = 'SELECT annual_leave_balance, medical_leave_balance, other_leave_balance FROM leave_balance WHERE user_id = ?';
    
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
                other_leave_balance: parseFloat(leaveBalance.other_leave_balance)
            }
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
app.post('/submit-leave-request', (req, res) => {
    let { leave_type_id, start_date, end_date, half_day, reason, user_id } = req.body;

    if (!user_id){
        user_id = 1
    }
    
    // Basic validation
    if (!leave_type_id || !start_date || !end_date || !reason || !user_id) {
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
    
    if (startDate < today) {
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
        
        // Check for overlapping leave requests
        const overlapQuery = `
            SELECT id, start_date, end_date, leave_type_id 
            FROM leave_request 
            WHERE user_id = ? 
            AND (
                (start_date <= ? AND end_date >= ?) OR
                (start_date <= ? AND end_date >= ?) OR
                (start_date >= ? AND end_date <= ?)
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
            
            // Check leave balance
            const balanceQuery = `SELECT ${balanceField} FROM leave_balance WHERE user_id = ?`;
            db.query(balanceQuery, [user_id], (err, balanceResult) => {
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
            
            const currentBalance = balanceResult[0][balanceField];
            if (currentBalance < numberOfDays) {
                return db.rollback(() => {
                    res.status(400).json({ 
                        success: false, 
                        message: `Insufficient leave balance. Available: ${currentBalance} days, Requested: ${numberOfDays} days` 
                    });
                });
            }
            
            // Insert leave request
            const insertQuery = `
                INSERT INTO leave_request 
                (request_date, leave_type_id, start_date, end_date, half_day, reason, number_of_days, user_id) 
                VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?)
            `;
            
            const insertValues = [
                leave_type_id,
                start_date,
                end_date,
                half_day || null,
                reason,
                numberOfDays,
                user_id
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
                
                // Update leave balance
                const updateQuery = `UPDATE leave_balance SET ${balanceField} = ${balanceField} - ? WHERE user_id = ?`;
                db.query(updateQuery, [numberOfDays, user_id], (err) => {
                    if (err) {
                        return db.rollback(() => {
                            console.error('Balance update error:', err);
                            res.status(500).json({ 
                                success: false, 
                                message: 'Error updating leave balance' 
                            });
                        });
                    }
                    
                    // Commit transaction
                    db.commit((err) => {
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
                            message: 'Leave request submitted successfully',
                            request_id: insertResult.insertId,
                            days_requested: numberOfDays
                        });
                    });
                });
            });
        });
        });
    });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});

