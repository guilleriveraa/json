// backend/db.js - PARA POSTGRESQL (Railway/Supabase)
const { Pool } = require('pg');
require('dotenv').config();

// Configuración robusta del pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false  // Necesario para Railway/Supabase
    },
    max: 10,                        // Máximo de conexiones en el pool
    idleTimeoutMillis: 30000,       // Cerrar conexiones inactivas después de 30s
    connectionTimeoutMillis: 5000,  // Timeout al conectar (5 segundos)
});

// Manejar errores del pool (SSL error, connection reset, etc.)
pool.on('error', (err) => {
    console.error('❌ Error en pool PostgreSQL:', err.message);
    // No hacemos nada, el pool intentará reconectar automáticamente
});

// Función query con reintento automático para errores de conexión
async function query(text, params) {
    try {
        return await pool.query(text, params);
    } catch (err) {
        // Si es error de conexión, reintentar una vez
        if (err.message.includes('SSL') ||
            err.message.includes('terminated') ||
            err.message.includes('Connection reset') ||
            err.message.includes('unexpected eof')) {

            console.log('🔄 Error de conexión PostgreSQL, reintentando...');
            console.log(`   Error: ${err.message}`);

            // Esperar 1 segundo y reintentar
            await new Promise(resolve => setTimeout(resolve, 1000));
            return await pool.query(text, params);
        }
        throw err;
    }
}

// Test conexión inicial
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Error conectando a PostgreSQL:', err.message);
    } else {
        console.log('✅ Conectado a PostgreSQL');
        release();
    }
});

// Exportar tanto el pool como la función query mejorada
module.exports = { pool, query };