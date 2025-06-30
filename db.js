import mysql from 'mysql2/promise.js';
import dotenv from 'dotenv';
dotenv.config();

const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// connect to database
(async () => { 
try {
  const connection = await pool.getConnection();
  console.log('Connected to the database');
  connection.release();
} catch (err) {
    console.error('Failed to connect to the database:', err.message)
}
})();
export default pool; 