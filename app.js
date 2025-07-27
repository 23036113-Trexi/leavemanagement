const express= require('express');
const mysql = require('mysql2');
const app = express();

// middleware to parse JSON
app.use(express.json());

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


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});

