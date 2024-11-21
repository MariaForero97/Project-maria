const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

require('dotenv').config();


const app = express();
app.use(express.json());
app.use(cors()); 

// Conexion db

let db;

function handleDisconnect() {
  db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectTimeout: 10000, 
    multipleStatements: true 
  });

  db.connect((err) => {
    if (err) {
      console.error('Error al conectar a la base de datos:', err);
      setTimeout(handleDisconnect, 2000); // Intenta reconectar después de 2 segundos
    } else {
      console.log('Conexión exitosa a la base de datos.');
    }
  });

  db.on('error', (err) => {
    console.error('Error en la conexión:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
      handleDisconnect(); // Reconecta automáticamente si la conexión se pierde
    } else {
      throw err; // Maneja otros errores
    }
  });

  setInterval(() => {
    db.query('SELECT 1', (err) => {
      if (err) {
        console.error('Error en el ping a la base de datos:', err);
      }
    });
  }, 5000); // Realiza un ping cada 5 segundos
}


handleDisconnect();


// Ruta para registrar usuarios
app.post('/register', async (req, res) => {
  const { Nombre, Correo, Contraseña, TipoUsuario } = req.body;

  // Validar que todos los campos estén presentes
  if (!Nombre || !Correo || !Contraseña || !TipoUsuario) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }

  try {
    // Verifica si el correo ya existe
    db.query('SELECT * FROM usuarios WHERE Correo = ?', [Correo], async (err, result) => {
      if (err) {
        console.error('Error al consultar la base de datos:', err);
        return res.status(500).json({ message: 'Error en el servidor' });
      }
      if (result.length > 0) {
        return res.status(400).json({ message: 'El correo ya está registrado' });
      }

      // Cifra la contraseña
      const hashedPassword = await bcrypt.hash(Contraseña, 8);

      // Inserta el nuevo usuario
      db.query(
        'INSERT INTO usuarios SET ?',
        { Nombre, Correo, Contraseña: hashedPassword, TipoUsuario },
        (err, result) => {
          if (err) {
            console.error('Error al insertar en la base de datos:', err);
            return res.status(500).json({ message: 'Error al registrar usuario' });
          }
          res.status(201).json({ message: 'Usuario registrado con éxito' });
        }
      );
    });
  } catch (error) {
    console.error('Error inesperado:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});


// Ruta para iniciar sesión
app.post('/login', (req, res) => {
  const { Correo, Contraseña } = req.body;

  db.query('SELECT * FROM usuarios WHERE Correo = ?', [Correo], async (err, result) => {
    if (err) return res.status(500).send('Error en el servidor');
    if (result.length === 0) return res.status(400).send('Usuario no encontrado');

    const user = result[0];

    // Verifica la contraseña
    const isMatch = await bcrypt.compare(Contraseña, user.Contraseña);
    if (!isMatch) return res.status(400).send('Contraseña incorrecta');

    // Genera un token JWT
    const token = jwt.sign({ id: user.ID_Usuario }, 'secreto_jwt', { expiresIn: '1h' });
    res.json({ token });
  });
});

// Inicia el servidor en el puerto 5000
app.listen(5000, () => {
  console.log('Servidor iniciado en el puerto 5000');
});
