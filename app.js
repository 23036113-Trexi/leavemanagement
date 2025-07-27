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


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});

