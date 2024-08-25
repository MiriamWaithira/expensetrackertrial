//importing the variables
const express = require('express');
const mysql = require('mysql2/promise');
// the above line was used to provide promise-based API to use
// asyn/await for handling asynchronous database operations.
// this makes the code cleaner and easier to read instead of using callbacks
const path = require('path');//path for the css was already declared in the .html files for login and register
const bcryptjs = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');
const crypto = require('crypto'); // For generating a random secret key

dotenv.config();

//create the instance for express
const app = express();
const port = 3400;

// Generate a strong random secret key
const secretKey = crypto.randomBytes(32).toString('hex');
// console.log('Your secret key:', secretKey);
// the above line was used to generate the session key once then stored in the .env file

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse incoming data (URL-encoded and JSON)
//this line is for extracting data from the form submissions for it to be available in my application
app.use(express.urlencoded({ extended: false }));
app.use(express.json())//for parsing the json data to be available in my express application


// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false, //to avoid creating empty sessions
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Set to false if using HTTP and true if HTTPS
    httpOnly: true, //prevent javascript from accessing the cookie
    maxAge: 1000 * 60 * 60 *24 //cookie expiration time ( 1 day )
    }
}));

// Connect to the database
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});


// Define database queries
const createUserTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL
  );
`;

// changed the table to be named costs because MySQL is case-sensitive
const createCostsTableQuery = `
  CREATE TABLE IF NOT EXISTS costs (
    cost_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    date DATE NOT NULL,
    category VARCHAR(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );
`;

// Create tables (if they don't exist)
db.query(createUserTableQuery)
  .then(() => console.log("Users table created successfully"))
  .catch(err => console.error("Error creating users table:", err));

db.query(createCostsTableQuery)
  .then(() => console.log("Costs table created successfully"))
  .catch(err => console.error("Error creating costs table:", err));


// Landing page route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login page route
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'Login.html'));
});

// Register page route
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'Register.html'));
});

// Register user route with password hashing
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcryptjs.hash(password, 10);
    await db.query('INSERT INTO users SET ?', { username, password: hashedPassword });
    res.redirect('/login'); // Redirect to login page after successful registration
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Login user route with authentication and session management
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    try {
      const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
      if (rows.length === 0) {
        return res.status(401).send("Invalid Credentials"); // User not found
      }
  
      const user = rows[0];
      const isMatch = await bcryptjs.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).send("Invalid Credentials"); // Incorrect password
      }
  
      req.session.user = { id: user.user_id, username: user.username };
      console.log('Session after login:', req.session); // Debug line
      res.redirect('/'); // Adjust as needed
    } catch (err) {
      console.error("Error logging in user:", err);
      res.status(500).send("Internal Server Error");
    }
  });
  


// Home page route (protected)
app.get('/home', async (req, res) => {
    try {
      if (req.session.user && req.session.user.id) {
        const [results] = await db.query('SELECT * FROM costs WHERE user_id = ?', [req.session.user.id]);
        res.sendFile(path.join(__dirname, 'public', 'index.html')); // Serve index.html after login
      } else {
        res.status(401).send('Unauthorized');
      }
    } catch (err) {
      console.error('Error fetching costs:', err);
      res.status(500).send('Internal Server Error');
    }
});



// Route to add a new cost
app.post('/costs', async (req, res) => {
    if (req.session.user && req.session.user.id) {
      const userId = req.session.user.id;
      const { amount, date, category } = req.body;
  
      if (!amount || !date || !category) {
        return res.status(400).json({ message: 'Missing required fields' });
      }
  
      try {
        await db.query('INSERT INTO costs (user_id, amount, date, category) VALUES (?, ?, ?, ?)', [userId, amount, date, category]);
        res.json({ message: 'Cost added successfully' });
      } catch (err) {
        console.error('Error adding cost:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  });
  





// Route to view user's costs
app.get('/costs', async (req, res) => {
    if (req.session.user && req.session.user.id) {
      const userId = req.session.user.id;
  
      try {
        const [results] = await db.query('SELECT * FROM costs WHERE user_id = ?', [userId]);
        res.json(results);
      } catch (err) {
        console.error('Error fetching costs:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  });
  


app.listen(port, () => {
  console.log(`Server is running at localhost://${port}`);
});


