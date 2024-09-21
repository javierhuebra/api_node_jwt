import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();

const PORT = process.env.PORT || 3001;

// Middleware para parsear JSON
app.use(express.json());

// Ruta principal
app.get('/ping', (req, res) => {
    res.json({ message: 'API con Express funcionando piola' });
});

// Servidor escuchando en el puerto
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Este sería el usuario almacenado en la base de datos (simulación)
const users = [
    {
        id: 1,
        username: 'admin',
        password: bcrypt.hashSync('password123', 8) // Contraseña encriptada
    }
];

// Clave secreta para firmar los tokens
const SECRET_KEY = 'mi_clave_secreta';

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Buscar el usuario en la base de datos
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    // Comparar la contraseña ingresada con la almacenada
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // Generar un token JWT si la contraseña es válida
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, {
        expiresIn: 86400 // Expira en 24 horas
    });

    res.status(200).json({ auth: true, token: token });
});

// Middleware para verificar el token JWT
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];  // Revisamos el header Authorization
    if (!authHeader) {
        return res.status(403).json({ message: 'No se proporcionó un token' });
    }

    // El token debería venir en el formato "Bearer <token>"
    const token = authHeader.split(' ')[1];  // Extraemos el token ignorando "Bearer"
    
    if (!token) {
        return res.status(403).json({ message: 'Formato de token incorrecto' });
    }

    // Verificar el token
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(500).json({ message: 'Error al autenticar el token' });
        }
        // Si el token es válido, almacena la información del usuario decodificada
        req.userId = decoded.id;
        next(); // Continuar al siguiente middleware o controlador
    });
}


// Proteger un endpoint con el middleware `verifyToken`
app.get('/protected', verifyToken, (req, res) => {
    res.status(200).json({ message: 'Este es un endpoint protegido', userId: req.userId });
});