const sql = require('mssql');

// Configuração do banco de dados para Azure SQL
const config = {
    user: process.env.DB_USER || 'CloudSA6d9c620d',
    password: process.env.DB_PASSWORD || 'Aa545454',
    server: process.env.DB_SERVER || 'gdm-stn-bd.database.windows.net', // Força o valor diretamente para teste
    database: process.env.DB_DATABASE || 'gdm-stn-bd',
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
