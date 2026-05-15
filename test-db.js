require('dotenv').config({ path: '.env.local' });
const { Client } = require('pg');

const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
  try {
    await client.connect();
    const res = await client.query('SELECT version()');
    console.log('✓ Qoşuldu:', res.rows[0].version);
  } catch (err) {
    console.error('✗ Xəta:', err.message);
  } finally {
    await client.end();
  }
})();