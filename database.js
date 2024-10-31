const sql = require('mssql');

// Configuração do banco de dados para Azure SQL
const config = {
    user: process.env.DB_USER || '',
    password: process.env.DB_PASSWORD || '',
    server: process.env.DB_SERVER || '', // Força o valor diretamente para teste
    database: process.env.DB_DATABASE || '',
    options: {
        encrypt: true,
        trustServerCertificate: false
    }
};

// Função para conectar ao banco de dados
const connect = async () => {
    try {
        const pool = await sql.connect(config);
        console.log('Conectado ao banco de dados Azure SQL com sucesso');
        return pool;
    } catch (err) {
        console.error('Erro ao conectar ao banco de dados Azure SQL:', err);
        throw err;
    }
};

module.exports = {
    connect
};
