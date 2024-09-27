const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db'); // Cấu hình kết nối MariaDB
const LoginRequest = require('./LoginRequest'); // Import class
const cors = require('cors')

const app = express();

app.use(express.json());

const secret_key = '7DBJbh5vyezHjaWtyt44Xem/2/DteVxYKOPSIAPPrsO1NFzxn6P5Xb/MEIPIaMG6';

app.use(cors({
    origin: 'http://localhost:3000', // Địa chỉ frontend của bạn
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Các phương thức được cho phép
    credentials: true // Cho phép cookie và xác thực
}));

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401); // Không có token, trả về 401

    jwt.verify(token, secret_key, (err, user) => {
        if (err) return res.sendStatus(403); // Token không hợp lệ, trả về 403
        req.user = user;
        next(); // Tiếp tục đến middleware hoặc route tiếp theo
    });
}

app.post('/api/login', async (req, res) => {
    try {
        // Tạo đối tượng LoginRequest từ req.body
        const loginRequest = new LoginRequest(req.body.username, req.body.password);

        // Gọi phương thức validate để kiểm tra dữ liệu
        loginRequest.validate();

        let conn = await db.getConnection();
        const user = await conn.query('SELECT * FROM user WHERE username = ?', [loginRequest.username]);

        if (user.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // So sánh mật khẩu
        const isPasswordValid = await bcrypt.compare(loginRequest.password, user[0].password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Tạo JWT token
        const access_token = jwt.sign({ id: user[0].id, role: user[0].role }, secret_key, { expiresIn: '1h' });
        res.json({ access_token });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.get('/api/users', authenticateToken, (req, res) => {
    // Giả sử bạn có một hàm để lấy người dùng từ database
    getUsersFromDatabase((users) => {
        res.json(users);
    });
});

// Chạy server
app.listen(5000, () => {
    console.log('Server is running on port 5000');
});
