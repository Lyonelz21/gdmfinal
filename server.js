const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { connect } = require('./database'); // Importa a função de conexão do database.js
const sql = require('mssql');
const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;
const fs = require('fs');

app.use(express.static('public')); // Define a pasta 'public' como estática

app.get('/', (req, res) => {
    res.redirect('/login.html'); // Ajuste o caminho se login.html estiver em uma pasta
});

require('dotenv').config();
console.log("Servidor:", process.env.DB_SERVER); // Deve mostrar "seuservidor.database.windows.net" ou o valor correto

// Conectar ao banco de dados e definir pool
let pool;
connect().then(connection => {
    pool = connection;
}).catch(err => {
    console.error("Erro ao estabelecer conexão com o banco de dados:", err);
});

// Configuração para servir arquivos estáticos
app.use(express.static(path.join(__dirname, 'public'))); // Substitua 'public' pela pasta onde estão os HTML

// Configuração do CORS
app.use(cors());

// Configuração de middleware para parse de JSON e URL-encoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuração da sessão
app.use(session({
    secret: 'sua_chave_secreta',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },  // Use secure: true em produção com HTTPS
    name: 'sessionId'  // Especifique um nome para identificar a sessão
}));

console.log("Sessão configurada");

// Redireciona a rota raiz para /login.html
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

function checkSession(req, res, next) {
    if (req.session && req.session.user) {
        next();
    } else {
        res.redirect('/login.html'); // Redireciona caso a sessão não esteja ativa
    }
}

// Middleware de autenticação
function isAuthenticated(req, res, next) {
    console.log("Verificação de autenticação:", req.session.user);  // Log da sessão
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'Usuário não autenticado' });
    }
}

// Middleware para verificar se o usuário é admin
function checkAdmin(req, res, next) {
    console.log("Verificação de admin - role:", req.session.user.role);  // Log da role do usuário

    if (req.session.user && req.session.user.role === 'admin') {
        next();
    } else {
        console.log("Acesso negado - redirecionando para login.");
        res.redirect('/login.html'); // Redireciona explicitamente para login
    }
}

// Exemplo de rota protegida
app.get('/criar-usuario.html', isAuthenticated, checkAdmin, (req, res) => {
    console.log("Acesso concedido à página criar-usuario.html para:", req.session.user);
    res.sendFile(path.join(__dirname, 'public', 'criar-usuario.html'));
});

// Rota para login com bcrypt
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool
            .request()
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM users WHERE username = @username');

        const user = result.recordset[0];

        if (user && await bcrypt.compare(password, user.password)) {
            // Armazena o `unit_id` na sessão
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role,
                unit_id: user.unit_id // Adiciona unit_id
            };
            res.json({ message: 'Login bem-sucedido', role: user.role });
        } else {
            res.status(401).json({ error: 'Usuário ou senha incorretos' });
        }
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});


// Rota para logout
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Erro ao encerrar sessão');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login.html');
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Erro ao encerrar a sessão:', err);
            return res.status(500).send('Erro ao encerrar a sessão');
        }
        res.redirect('/login.html'); // Redireciona para a página de login após o logout
    });
});

// Rota para criar usuário (apenas admin)
app.post('/create-user', isAuthenticated, checkAdmin, async (req, res) => {
    const { username, password, role, name, phone, email } = req.body;

    try {
        // Criptografa a senha
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Conecta ao banco de dados
        const pool = await connect();

        // Insere o usuário sem definir `id` (deixe o banco gerar automaticamente)
        await pool.request()
            .input('username', sql.VarChar, username)
            .input('password', sql.VarChar, hashedPassword)
            .input('unit_id', sql.Int, null) // Define `unit_id` como NULL
            .input('role', sql.VarChar, role)
            .input('name', sql.VarChar, name)
            .input('phone', sql.VarChar, phone)
            .input('email', sql.VarChar, email)
            .query(`
                INSERT INTO users (username, password, unit_id, role, name, phone, email)
                VALUES (@username, @password, @unit_id, @role, @name, @phone, @email)
            `);

        console.log('Usuário criado com sucesso');
        res.json({ message: 'Usuário criado com sucesso!' });
    } catch (err) {
        console.error('Erro ao criar usuário:', err);
        res.status(500).json({ error: 'Erro no servidor ao criar usuário.' });
    }
});

// Rota para listar todos os usuários (para gerenciamento de usuários)
app.get('/users', isAuthenticated, checkAdmin, async (req, res) => {
    try {
        const pool = await connect();
        const result = await pool.request().query('SELECT * FROM users');
        res.json(result.recordset);
    } catch (err) {
        console.error('Erro ao listar usuários:', err);
        res.status(500).send('Erro no servidor');
    }
});

// Rota para editar usuário (apenas admin)
app.post('/edit-user/:id', isAuthenticated, checkAdmin, async (req, res) => {
    const userId = req.params.id;
    const { name, phone, email } = req.body;

    try {
        const pool = await connect();
        await pool.request()
            .input('userId', sql.Int, userId)
            .input('name', sql.VarChar, name)
            .input('phone', sql.VarChar, phone)
            .input('email', sql.VarChar, email)
            .query(`
                UPDATE users SET name = @name, phone = @phone, email = @email WHERE id = @userId
            `);

        res.redirect('/gerenciamento-usuarios.html');
    } catch (err) {
        console.error('Erro ao editar usuário:', err);
        res.status(500).send('Erro no servidor');
    }
});

// Rota para deletar usuário (apenas admin)
app.post('/delete-user/:id', isAuthenticated, checkAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        const pool = await connect();
        await pool.request()
            .input('userId', sql.Int, userId)
            .query('DELETE FROM users WHERE id = @userId');

        res.redirect('/gerenciamento-usuarios.html');
    } catch (err) {
        console.error('Erro ao deletar usuário:', err);
        res.status(500).send('Erro no servidor');
    }
});

// Configuração do multer para upload de arquivos PDF
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        const fileTypes = /pdf/;
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = fileTypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Apenas arquivos PDF são permitidos!'));
        }
    }
});

app.use(express.static(path.join(__dirname, 'public')));

// Expor a pasta de uploads para acesso ao PDF
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.get('/cadastro-material', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/cadastro-material.html'); // ou o caminho para o arquivo HTML
});

// Rota para cadastro de GDM com upload de PDF
app.post('/cadastro-material', checkSession, upload.single('gdmFile'), async (req, res) => {
        console.log("Sessão ativa ao cadastrar material:", req.session.user);
    try {
        const pool = await connect();  // Garante a conexão antes da requisição

        const { numeroGDM, motivoDesembarque, destino, observacao, dataEnvio } = req.body;
        const gdmFile = req.file ? req.file.filename : null;
        const unitId = req.session.user.unit_id; // Supondo que o unit_id está em req.session.user

        await pool.request()
            .input('numeroGDM', sql.VarChar, numeroGDM)
            .input('motivoDesembarque', sql.VarChar, motivoDesembarque)
            .input('destino', sql.VarChar, destino)
            .input('observacao', sql.Text, observacao)
            .input('dataEnvio', sql.Date, dataEnvio)
            .input('gdmFile', sql.VarChar, gdmFile)
            .input('unitId', sql.Int, unitId)
            .query(`
                INSERT INTO gdms (numero_gdm, motivo_desembarque, destino, observacao, data_envio, gdm_file, unit_id)
                VALUES (@numeroGDM, @motivoDesembarque, @destino, @observacao, @dataEnvio, @gdmFile, @unitId)
            `);

        res.status(200).json({ message: 'Material cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro ao cadastrar material:', err);
        res.status(500).json({ error: 'Erro ao cadastrar material' });
    }
});

// Rota para listar GDMs com filtro de unidade
app.get('/gdm-list', isAuthenticated, async (req, res) => {
    try {
        const pool = await connect();
        const unitFilter = req.query.unit;
        let query = 'SELECT * FROM gdms';
        if (unitFilter) {
            query += ' WHERE created_by = @unit';
        }
        
        const result = await pool.request()
            .input('unit', sql.Int, unitFilter)
            .query(query);
        
        res.json(result.recordset);
    } catch (err) {
        console.error('Erro ao listar GDMs:', err);
        res.status(500).send('Erro no servidor');
    }
});

// Rota para o dashboard com métricas de tempo médio
app.get('/dashboard-metrics', isAuthenticated, async (req, res) => {
    try {
        const pool = await connect();
        const retornoResult = await pool.request().query(`
            SELECT AVG(DATEDIFF(day, data_envio, data_retorno)) AS tempoMedioRetorno
            FROM gdms
            WHERE data_retorno IS NOT NULL
        `);
        
        const abertoResult = await pool.request().query(`
            SELECT AVG(DATEDIFF(day, data_envio, GETDATE())) AS tempoMedioAberto
            FROM gdms
            WHERE data_retorno IS NULL
        `);

        res.json({
            tempoMedioRetorno: retornoResult.recordset[0].tempoMedioRetorno,
            tempoMedioAberto: abertoResult.recordset[0].tempoMedioAberto
        });
    } catch (err) {
        console.error('Erro ao calcular métricas:', err);
        res.status(500).send('Erro no servidor');
    }
});

// Rota para atualizar o status da GDM
app.post('/api/atualizar-status', async (req, res) => {
    const { gdmNumero, motivo, dataRetorno } = req.body;

    try {
        // Atualiza o status_motivo e a data de retorno no banco de dados
        const pool = await connect();
        const query = `
            UPDATE gdms
            SET status_motivo = @motivo,
                data_retorno = @dataRetorno
            WHERE numero_gdm = @gdmNumero
        `;

        await pool.request()
            .input('motivo', sql.VarChar, motivo)
            .input('dataRetorno', sql.Date, dataRetorno)
            .input('gdmNumero', sql.Int, gdmNumero)
            .query(query);

        res.json({ message: 'Status atualizado com sucesso.' });
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
        res.status(500).json({ error: 'Erro ao atualizar status.' });
    }
});

// Rota para editar um usuário
app.post('/api/users/:id/edit', isAuthenticated, checkAdmin, async (req, res) => {
    const userId = req.params.id;
    const { name, phone, email } = req.body;

    try {
        const pool = await connect();
        await pool.request()
            .input('id', sql.Int, userId)
            .input('name', sql.VarChar, name)
            .input('phone', sql.VarChar, phone)
            .input('email', sql.VarChar, email)
            .query(`
                UPDATE users
                SET name = @name, phone = @phone, email = @email
                WHERE id = @id
            `);

        res.json({ message: 'Usuário atualizado com sucesso!' });
    } catch (err) {
        console.error('Erro ao atualizar usuário:', err);
        res.status(500).json({ error: 'Erro no servidor ao atualizar usuário.' });
    }
});

// Rota para alterar a senha do usuário
app.post('/api/users/:id/change-password', isAuthenticated, checkAdmin, async (req, res) => {
    const userId = req.params.id;
    const { password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const pool = await connect();
        await pool.request()
            .input('id', sql.Int, userId)
            .input('password', sql.VarChar, hashedPassword)
            .query(`
                UPDATE users
                SET password = @password
                WHERE id = @id
            `);

        res.json({ message: 'Senha alterada com sucesso!' });
    } catch (err) {
        console.error('Erro ao alterar a senha:', err);
        res.status(500).json({ error: 'Erro no servidor ao alterar senha.' });
    }
});

// Rota para excluir um usuário
app.delete('/api/users/:id', isAuthenticated, checkAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        const pool = await connect();
        await pool.request()
            .input('id', sql.Int, userId)
            .query(`
                DELETE FROM users
                WHERE id = @id
            `);

        res.json({ message: 'Usuário excluído com sucesso!' });
    } catch (err) {
        console.error('Erro ao excluir usuário:', err);
        res.status(500).json({ error: 'Erro no servidor ao excluir usuário.' });
    }
});

// Rota para listar todos os usuários
app.get('/api/users', isAuthenticated, checkAdmin, async (req, res) => {
    try {
        const pool = await connect();
        const result = await pool.request().query('SELECT id, username, name, phone, email FROM users');
        res.json(result.recordset);
    } catch (err) {
        console.error('Erro ao buscar usuários:', err);
        res.status(500).json({ error: 'Erro no servidor ao buscar usuários.' });
    }
});

// Rota para acessar o nome e role do usuário
app.get('/api/user-info', (req, res) => {
    console.log("Dados da sessão:", req.session.user); // Adiciona log para verificar o que está na sessão
    if (req.session.user) {
        res.json({ name: req.session.user.username, role: req.session.user.role });
    } else {
        res.status(401).json({ error: 'Usuário não autenticado' });
    }
});

// Rota para obter GDMs em aberto
app.get('/api/gdms/abertos', async (req, res) => {
    try {
        const result = await pool.request()
            .query('SELECT * FROM gdms WHERE data_retorno IS NULL'); // Ajuste conforme necessário
        res.json(result.recordset);
    } catch (error) {
        console.error('Erro ao buscar GDMs em aberto:', error);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// Rota para atualizar o status da GDM
app.post('/api/gdm/update-status', async (req, res) => {
    const { gdmId, statusMotivo, dataRetorno } = req.body;
    try {
        await pool.request()
            .input('id', sql.Int, gdmId)
            .input('statusMotivo', sql.VarChar, statusMotivo)
            .input('dataRetorno', sql.Date, dataRetorno)
            .query('UPDATE gdms SET status_motivo = @statusMotivo, data_retorno = @dataRetorno WHERE id = @id');

        res.json({ message: 'Status atualizado com sucesso!' });
    } catch (error) {
        console.error('Erro ao atualizar status da GDM:', error);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

app.get('/api/lista-gdm', isAuthenticated, async (req, res) => {
    try {
        const pool = await connect();

        let query = `
            SELECT g.id, g.numero_gdm, g.motivo_desembarque, g.destino, g.data_envio, g.data_retorno, g.status_motivo,
                   u.username AS embarcacao, g.observacao
            FROM gdms g
            LEFT JOIN users u ON g.unit_id = u.unit_id
        `;

        const parameters = [];

        if (req.session.user.role === 'admin' || req.session.user.role === 'terra') {
            // Para admin e terra, verifica se há um filtro de embarcação aplicado
            if (req.query.embarcacao) {
                query += ` WHERE g.unit_id = @unit_id`;
                parameters.push({ name: 'unit_id', type: sql.Int, value: req.query.embarcacao });
            }
        } else {
            // Para embarcação, exibe apenas as GDMs do próprio usuário
            query += ` WHERE g.unit_id = @unit_id`;
            parameters.push({ name: 'unit_id', type: sql.Int, value: req.session.user.unit_id });
        }

        const request = pool.request();
        parameters.forEach(param => request.input(param.name, param.type, param.value));

        const result = await request.query(query);

        res.json(result.recordset);
    } catch (error) {
        console.error('Erro ao buscar GDMs:', error);
        res.status(500).json({ error: 'Erro ao buscar a lista de GDMs' });
    }
});


// Função para calcular o tempo médio de retorno e o tempo médio de GDMs em aberto
async function calcularMetricasDashboard() {
    try {
        const pool = await connect();

        // Tempo médio de retorno (GDMs que possuem uma data de retorno registrada)
        const tempoRetornoResult = await pool.request()
            .query(`
                SELECT AVG(DATEDIFF(DAY, data_envio, data_retorno)) AS tempoMedioRetorno
                FROM gdms
                WHERE data_retorno IS NOT NULL
            `);

        const tempoMedioRetorno = tempoRetornoResult.recordset[0].tempoMedioRetorno;

        // Tempo médio de GDMs em aberto (GDMs que não possuem data de retorno)
        const tempoAbertoResult = await pool.request()
            .query(`
                SELECT AVG(DATEDIFF(DAY, data_envio, GETDATE())) AS tempoMedioAberto
                FROM gdms
                WHERE data_retorno IS NULL
            `);

        const tempoMedioAberto = tempoAbertoResult.recordset[0].tempoMedioAberto;

        return { tempoMedioRetorno, tempoMedioAberto };
    } catch (error) {
        console.error("Erro ao calcular métricas do dashboard:", error);
        throw error;
    }
}

// Rota para retornar as métricas do dashboard
app.get('/dashboard-metrics', isAuthenticated, async (req, res) => {
    try {
        const metrics = await calcularMetricasDashboard();
        res.json(metrics);
    } catch (error) {
        res.status(500).json({ error: "Erro ao calcular métricas do dashboard." });
    }
});

// Função para GDMs por Embarcação
app.get('/gdm-por-embarcacao', async (req, res) => {
    try {
        const pool = await connect();
        const result = await pool.request()
            .query(`
                SELECT u.username AS embarcacao, COUNT(g.unit_id) AS quantidade
                FROM gdms g
                JOIN users u ON g.unit_id = u.unit_id
                GROUP BY u.username
            `);

        const embarcacoes = result.recordset.map(row => row.embarcacao.charAt(0).toUpperCase() + row.embarcacao.slice(1));
        const quantidades = result.recordset.map(row => row.quantidade);

        res.json({ embarcacoes, quantidades });
    } catch (error) {
        console.error('Erro ao buscar GDMs por embarcação:', error);
        res.status(500).json({ error: 'Erro ao buscar GDMs por embarcação.' });
    }
});

// Função para GDMs por Mês
app.get('/gdm-por-mes', async (req, res) => {
    try {
        const pool = await connect();
        const result = await pool.request()
            .query(`SELECT FORMAT(data_envio, 'yyyy-MM') AS mes, COUNT(*) AS quantidade FROM gdms GROUP BY FORMAT(data_envio, 'yyyy-MM') ORDER BY mes`);

        const meses = result.recordset.map(row => row.mes);
        const quantidades = result.recordset.map(row => row.quantidade);

        res.json({ meses, quantidades });
    } catch (error) {
        console.error('Erro ao buscar GDMs por mês:', error);
        res.status(500).json({ error: 'Erro ao buscar GDMs por mês.' });
    }
});

// Função para Materiais Desembarcados
app.get('/materiais-desembarcados', async (req, res) => {
    try {
        const pool = await connect();
        const result = await pool.request()
            .query(`SELECT status_motivo AS tipo, COUNT(*) AS quantidade FROM gdms GROUP BY status_motivo`);

        const tipos = result.recordset.map(row => row.tipo);
        const quantidades = result.recordset.map(row => row.quantidade);

        res.json({ tipos, quantidades });
    } catch (error) {
        console.error('Erro ao buscar materiais desembarcados:', error);
        res.status(500).json({ error: 'Erro ao buscar materiais desembarcados.' });
    }
});

app.get('/api/embarcacoes', async (req, res) => {
    try {
        const pool = await connect();
        const result = await pool.request().query(`
            SELECT DISTINCT unit_id, username
            FROM users
            WHERE role = 'embarcacao'
        `);

        res.json(result.recordset);
    } catch (error) {
        console.error('Erro ao buscar embarcações:', error);
        res.status(500).json({ error: 'Erro ao buscar embarcações.' });
    }
});

// Rota para obter detalhes de uma GDM específica
app.get('/api/detalhe-gdm/:id', isAuthenticated, async (req, res) => {
    const gdmId = parseInt(req.params.id, 10); // Garante que é um número inteiro

    if (isNaN(gdmId)) {
        return res.status(400).json({ error: 'ID inválido para GDM' });
    }

    try {
        const pool = await connect();
        const result = await pool.request()
            .input('id', sql.Int, gdmId)
            .query(`
                SELECT g.numero_gdm, u.username AS unidade, g.motivo_desembarque, g.destino,
                       g.observacao, g.data_envio, g.data_retorno, g.gdm_file, g.status_motivo
                FROM gdms g
                LEFT JOIN users u ON g.unit_id = u.unit_id
                WHERE g.id = @id;
            `);

        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'GDM não encontrada' });
        }

        res.json(result.recordset[0]);
    } catch (error) {
        console.error('Erro ao buscar detalhes da GDM:', error);
        res.status(500).json({ error: 'Erro ao buscar detalhes da GDM' });
    }
});

app.use('/api/gdms-pendentes', isAuthenticated);

// Rota para listar GDMs pendentes de atualização de status (sem data de retorno)
app.get('/api/detalhe-gdm/:id', isAuthenticated, async (req, res) => {
    const gdmId = parseInt(req.params.id, 10); // Garante que é um número inteiro

    if (isNaN(gdmId)) {
        return res.status(400).json({ error: 'ID inválido para GDM' });
    }

    try {
        const pool = await connect();
        const result = await pool.request()
            .input('id', sql.Int, gdmId)
            .query(`
                SELECT 
                    g.numero_gdm, 
                    u.username AS unidade, -- Pega o nome do usuário (embarcação) associado ao unit_id
                    g.motivo_desembarque, 
                    g.destino,
                    g.observacao, 
                    g.data_envio, 
                    g.data_retorno, 
                    g.gdm_file, 
                    g.status_motivo
                FROM gdms g
                LEFT JOIN users u ON g.unit_id = u.unit_id -- Verifica se o unit_id da GDM é igual ao unit_id da users
                WHERE g.id = @id;
            `);

        // Verifica se algum resultado foi encontrado
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'GDM não encontrada' });
        }

        // Formata a resposta com os dados da GDM
        const gdmDetails = {
            numero_gdm: result.recordset[0].numero_gdm,
            unidade: result.recordset[0].unidade || 'Unidade desconhecida', // Exibe unidade ou valor padrão se estiver undefined
            motivo_desembarque: result.recordset[0].motivo_desembarque,
            destino: result.recordset[0].destino,
            observacao: result.recordset[0].observacao || 'Nenhuma observação',
            data_envio: result.recordset[0].data_envio,
            data_retorno: result.recordset[0].data_retorno || 'Não retornado',
            gdm_file: result.recordset[0].gdm_file,
            status_motivo: result.recordset[0].status_motivo || 'Sem status'
        };

        // Envia os detalhes da GDM
        res.json(gdmDetails);
    } catch (error) {
        console.error('Erro ao buscar detalhes da GDM:', error);
        res.status(500).json({ error: 'Erro ao buscar detalhes da GDM' });
    }
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
