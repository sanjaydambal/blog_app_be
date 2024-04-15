const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();
const app = express();
const jwt = require('jsonwebtoken');
const PORT = process.env.PORT || 5000;
const cors = require('cors');
app.use(cors());
// PostgreSQL connection pool
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432, // Default PostgreSQL port
    ssl: {
        rejectUnauthorized: false, // Set to false if using self-signed certificates
        // You may need to provide other SSL options such as ca, cert, and key
        // Example:
        // ca: fs.readFileSync('path/to/ca-certificate.crt'),
        // cert: fs.readFileSync('path/to/client-certificate.crt'),
        // key: fs.readFileSync('path/to/client-certificate.key')
    },
  });
  

// Middleware
app.use(bodyParser.json());

// Signup API
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if the email already exists
    const emailExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (emailExists.rows.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    await pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3)', [name, email, hashedPassword]);

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ message: 'Server Error' });
  }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token || !token.startsWith('Bearer ')) {
      return res.status(403).send({ message: 'Token not provided or invalid' });
    }
    
    const verifiedToken = token.split(' ')[1];
    jwt.verify(verifiedToken, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).send({ message: 'Failed to authenticate token' });
      }
  
      req.userId = decoded.userId;
      next();
    });
  };
  
  const createTableQuery = `
  CREATE TABLE IF NOT EXISTS blogs (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`;

pool.query(createTableQuery)
  .then(() => console.log('Table created successfully'))
  .catch(err => console.error('Error creating table:', err.message));

// Create a blog post
app.post('/blogs', async (req, res) => {
  const { title, content, author, timestamp } = req.body;
  try {
    const query = 'INSERT INTO blogs (title, content, author, timestamp) VALUES ($1, $2, $3, $4) RETURNING *';
    const result = await pool.query(query, [title, content, author, timestamp]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating blog post:', error.message);
    res.status(500).json({ message: 'Server Error' });
  }
});

// Get all blog posts
app.get('/blogs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM blogs ORDER BY timestamp DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error getting blog posts:', error.message);
    res.status(500).json({ message: 'Server Error' });
  }
});

// Update a blog post
app.put('/blogs/:id', async (req, res) => {
  const { id } = req.params;
  const { title, content, author, timestamp } = req.body;
  try {
    const query = 'UPDATE blogs SET title = $1, content = $2, author = $3, timestamp = $4 WHERE id = $5 RETURNING *';
    const result = await pool.query(query, [title, content, author, timestamp, id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Blog post not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating blog post:', error.message);
    res.status(500).json({ message: 'Server Error' });
  }
});

// Delete a blog post
app.delete('/blogs/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM blogs WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Blog post not found' });
    }
    res.status(200).json({ message: 'Blog post deleted successfully' });
  } catch (error) {
    console.error('Error deleting blog post:', error.message);
    res.status(500).json({ message: 'Server Error' });
  }
});





app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Check if the user with the provided email exists
      const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (user.rows.length === 0) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
  
      // Compare passwords
      const match = await bcrypt.compare(password, user.rows[0].password);
      if (!match) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
  
      // Generate JWT
      const token = jwt.sign({ userId: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
      // Send the token in the response
      res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
      console.error('Error:', error.message);
      res.status(500).json({ message: 'Server Error' });
    }
  });
  


// PostgreSQL query to create users table
const createUsersTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  )
`;

// Execute the query to create users table
pool.query(createUsersTableQuery)
  .then(() => {
    console.log('Users table created successfully');
  })
  .catch((error) => {
    console.error('Error creating users table:', error.message);
  });

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
