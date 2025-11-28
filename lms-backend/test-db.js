// test-db.js (verbose)
require('dotenv').config();
const mysql = require('mysql2/promise');

console.log('Running test-db.js');
console.log('Working dir:', process.cwd());
console.log('Node version:', process.version);
console.log('Env vars (DB_HOST, DB_USER, DB_NAME):', {
  DB_HOST: process.env.DB_HOST,
  DB_USER: process.env.DB_USER,
  DB_NAME: process.env.DB_NAME
});

(async () => {
  try {
    const conn = await mysql.createConnection({
      host: process.env.DB_HOST || '127.0.0.1',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASS || '',
      database: process.env.DB_NAME || ''
    });
    console.log('Connected to MySQL, running SHOW TABLES...');
    const [rows] = await conn.query('SHOW TABLES;');
    console.log('SHOW TABLES result count:', rows.length);
    console.dir(rows, { depth: 5 });
    await conn.end();
    console.log('Done.');
  } catch (err) {
    console.error('CONNECTION ERROR:');
    console.error(err && err.message ? err.message : err);
    if (err && err.code) console.error('Error code:', err.code);
    process.exit(1);
  }
})();
