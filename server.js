const express = require('express');
console.log('✅ Express cargado');

const cors = require('cors');
console.log('✅ CORS cargado');

const db = require('./db');
console.log('✅ DB cargada');

const jwt = require('jsonwebtoken');
console.log('✅ JWT cargado');

const bcrypt = require('bcryptjs');
console.log('✅ Bcrypt cargado');

const nodemailer = require('nodemailer');
console.log('✅ Nodemailer cargado');

require('dotenv').config();
console.log('✅ Dotenv configurado');

const validateEmail = require('./services/emailValidation');
console.log('✅ EmailValidation cargado');

const helmet = require('helmet');
console.log('✅ Helmet cargado');

const rateLimit = require('express-rate-limit');
console.log('✅ RateLimit cargado');

const { body, validationResult } = require('express-validator');
console.log('✅ Express-validator cargado');

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
console.log('✅ Stripe cargado');

const app = express();
console.log('✅ App creada');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
console.log('✅ Variables de entorno leídas');

// Manejador de errores NO CAPTURADOS
process.on('uncaughtException', (err) => {
    console.error('❌❌❌ ERROR NO CAPTURADO ❌❌❌');
    console.error('Nombre:', err.name);
    console.error('Mensaje:', err.message);
    console.error('Stack:', err.stack);
    console.error('❌❌❌ FIN DEL ERROR ❌❌❌');
});

// Manejador de promesas rechazadas NO CAPTURADAS
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌❌❌ PROMESA RECHAZADA NO CAPTURADA ❌❌❌');
    console.error('Razón:', reason);
    console.error('Promesa:', promise);
});

// Verificar JWT_SECRET
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET no está definido en .env');
    process.exit(1);
}
console.log('✅ JWT_SECRET verificado');

// Verificar variables de entorno críticas
const requiredEnv = ['JWT_SECRET', 'DATABASE_URL', 'STRIPE_SECRET_KEY'];
requiredEnv.forEach(envVar => {
    if (!process.env[envVar]) {
        console.error(`❌ Variable de entorno ${envVar} no definida`);
        process.exit(1);
    }
});
console.log('✅ Variables de entorno críticas verificadas');

// ===== CONFIGURACIÓN DE SEGURIDAD =====
console.log('🔒 Iniciando configuración de seguridad...');

// 1. Helmet - Protección de cabeceras HTTP
app.use(helmet());
console.log('✅ Helmet configurado');

// 2. Deshabilitar x-powered-by (oculta que usas Express)
app.disable('x-powered-by');
console.log('✅ x-powered-by deshabilitado');

// ===== CONFIGURACIÓN CORS MEJORADA =====
const corsOptions = {
    origin: process.env.NODE_ENV === 'production'
        ? [/\.vercel\.app$/]  // Acepta cualquier subdominio de vercel.app
        : ['http://localhost:5500', 'http://127.0.0.1:5500'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
};

// Aplicar CORS una sola vez (esto ya maneja OPTIONS automáticamente)
app.use(cors(corsOptions));
console.log('✅ CORS configurado con comodín para Vercel');

// 4. Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones desde esta IP, intenta más tarde.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: { error: 'Demasiados intentos de inicio de sesión. Intenta más tarde.' }
});
console.log('✅ Rate Limiters creados');

app.use('/api/', limiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
console.log('✅ Rate Limiting aplicado');
console.log('⚠️ Rate limiting desactivado para pruebas');

// ===== WEBHOOK DE STRIPE (VERSIÓN CORREGIDA) =====
console.log('📡 Configurando webhook de Stripe...');
// LOG TEMPORAL PARA VER QUÉ SECRETO USA EL SERVIDOR
console.log('🔑 STRIPE_WEBHOOK_SECRET cargado:', process.env.STRIPE_WEBHOOK_SECRET ? '✅ DEFINIDO' : '❌ NO DEFINIDO');
console.log('🔑 Longitud del secreto:', process.env.STRIPE_WEBHOOK_SECRET?.length);
console.log('🔑 Primeros 10 chars:', process.env.STRIPE_WEBHOOK_SECRET?.substring(0, 10) + '...');
// --- NUEVO: Asegurar que el body se mantiene como raw ---
app.post('/webhook', express.raw({type: 'application/json'}),async (req, res) => {
  // --- NUEVO: Extraer la firma y el cuerpo raw antes de cualquier otra operación ---
  const sig = req.headers['stripe-signature'];
  // --- NUEVO: req.body es un Buffer. Lo pasamos directamente a constructEvent ---
  const rawBody = req.body;

  console.log('🔔 Webhook recibido');
  console.log('📦 Tipo de req.body:', typeof rawBody);
  console.log('📦 req.body es Buffer?', Buffer.isBuffer(rawBody));
  console.log('📦 Longitud del body:', rawBody.length);
  console.log('📦 Primeros 100 chars:', rawBody.toString('utf8').substring(0, 100).replace(/\n/g, ' '));
  console.log('📦 Stripe-Signature:', sig?.substring(0, 50));

  let event;

  try {
    // --- NUEVO: Pasar el Buffer directamente ---
    event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log('✅ Webhook verificado. Tipo:', event.type);
  } catch (err) {
    console.log(`❌ Error de firma del webhook: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    // --- El resto de tu lógica permanece IGUAL ---
    console.log('💰 Checkout completado');
    const session = event.data.object;
    
    const usuarioId = session.metadata.usuarioId;
    const carritoId = session.metadata.carritoId;
    const total = parseFloat(session.metadata.total);
    const descuento = parseFloat(session.metadata.descuento);
    const cuponId = session.metadata.cuponId || null;
    
    console.log(`✅ Pago completado para usuario ${usuarioId}`);
    console.log(`🛒 Carrito ID: ${carritoId}`);

    try {
      const direccionEnvio = [
        session.metadata.direccion_calle,
        session.metadata.direccion_piso,
        session.metadata.direccion_ciudad,
        session.metadata.direccion_cp,
        session.metadata.direccion_pais
      ].filter(Boolean).join(', ');

      const direccionDetalles = JSON.stringify({
        nombre: session.metadata.direccion_nombre || '',
        calle: session.metadata.direccion_calle || '',
        piso: session.metadata.direccion_piso || '',
        ciudad: session.metadata.direccion_ciudad || '',
        codigo_postal: session.metadata.direccion_cp || '',
        pais: session.metadata.direccion_pais || ''
      });

      console.log('📍 Dirección:', direccionEnvio || 'No especificada');

      // 1. VERIFICAR SI EL PEDIDO YA EXISTE PRIMERO
console.log('🔍 Verificando si el pedido ya existe...');
const { rows: existingOrder } = await db.query(
  'SELECT id FROM pedidos WHERE stripe_session_id = $1',
  [session.id]
);

let pedidoId;
if (existingOrder.length > 0) {
  pedidoId = existingOrder[0].id;
  console.log(`⚠️ Pedido ya existente ID: ${pedidoId} (stripe_session_id duplicado)`);
} else {
  // 2. Insertar nuevo pedido
  console.log('📝 Insertando nuevo pedido...');
  const { rows: pedidoRows } = await db.query(
    `INSERT INTO pedidos 
     (usuario_id, total, estado, fecha, direccion_envio, direccion_detalles, cupon_id, descuento_aplicado, stripe_session_id) 
     VALUES ($1, $2, 'pagado', NOW(), $3, $4, $5, $6, $7) 
     RETURNING id`,
    [usuarioId, total, direccionEnvio, direccionDetalles, cuponId, descuento, session.id]
  );
  pedidoId = pedidoRows[0].id;
  console.log(`🎉 Pedido nuevo creado ID: ${pedidoId}`);
}

// 3. Continuar con el resto (items, carrito, etc.)
if (pedidoId) {
  // 2. Obtener items del carrito
  console.log('🔍 Buscando items del carrito...');
  const { rows: items } = await db.query(
    `SELECT ci.cantidad, ci.precio_unitario, p.id as producto_id
     FROM cart_items ci
     JOIN productos p ON ci.producto_id = p.id
     WHERE ci.carrito_id = $1`,
    [carritoId]
  );
  console.log(`📦 Items encontrados: ${items.length}`);

  // 3. Guardar items
  if (items.length > 0) {
    console.log('💾 Guardando items...');
    for (const item of items) {
      await db.query(
        'INSERT INTO order_items (pedido_id, producto_id, cantidad, precio) VALUES ($1, $2, $3, $4)',
        [pedidoId, item.producto_id, item.cantidad, parseFloat(item.precio_unitario)]
      );
    }
    console.log('✅ Items guardados');
  }

  // 4. Actualizar cupón
  if (cuponId) {
    console.log('🎫 Actualizando cupón...');
    await db.query(
      'UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE id = $1',
      [cuponId]
    );
    console.log('✅ Cupón actualizado');
  }
}

      // 5. VACIAR CARRITO - CON LOGS EXHAUSTIVOS
      console.log('🧹 [DEBUG] Entrando en la sección de vaciado de carrito...');
      console.log(`🧹 [DEBUG] Intentando vaciar carrito con ID: ${carritoId} (tipo: ${typeof carritoId})`);

      if (!carritoId) {
        console.log('❌ [DEBUG] ERROR: carritoId es undefined o null. No se puede vaciar.');
      } else {
        try {
          console.log(`🧹 [DEBUG] Ejecutando: DELETE FROM cart_items WHERE carrito_id = ${carritoId}`);
          const deleteResult = await db.query('DELETE FROM cart_items WHERE carrito_id = $1', [carritoId]);
          console.log(`🧹 [DEBUG] Resultado de la consulta:`, deleteResult);
          console.log(`🧹 [DEBUG] Filas eliminadas: ${deleteResult.rowCount}`);
          
          if (deleteResult.rowCount > 0) {
            console.log('✅ ¡CARRITO VACIADO CON ÉXITO!');
          } else {
            console.log('⚠️ No se eliminó ninguna fila. ¿El carrito ya estaba vacío o no existía?');
          }
        } catch (err) {
          console.error('❌ [DEBUG] Error GORDO al intentar vaciar el carrito:', err);
        }
      }
      console.log('🧹 [DEBUG] Fin de la sección de vaciado de carrito.\n');
    } catch (err) {
      console.error('❌ Error en webhook:', err);
    }
  }

  res.json({received: true});
});
console.log('✅ Webhook configurado');

app.use(express.json());
console.log('✅ express.json() configurado');

// ===================== REGISTRO CON VALIDACIÓN =====================
console.log('🛣️ Configurando rutas...');

app.post('/api/register',
    [
        body('nombre').notEmpty().withMessage('El nombre es obligatorio').trim().escape(),
        body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
        body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
    ],
    async (req, res) => {
        console.log('📝 [REGISTER] Ruta llamada');
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('❌ [REGISTER] Errores de validación:', errors.array());
            return res.status(400).json({ 
                message: 'Error de validación', 
                errors: errors.array() 
            });
        }

        const { nombre, email, password } = req.body;

        try {
            console.log(`🔍 [REGISTER] Validando email: ${email}`);
            const validation = await validateEmail(email);
            
            if (!validation.isValid) {
                console.log('❌ [REGISTER] Email no válido:', validation.message);
                let message = 'El email no es válido';
                if (validation.isDisposable) {
                    message = 'No se permiten emails temporales o desechables';
                } else if (validation.isRoleBased) {
                    message = 'Usa un email personal, no uno de empresa';
                } else {
                    message = validation.message;
                }
                return res.status(400).json({ message });
            }

            console.log('🔍 [REGISTER] Verificando si email existe');
            const { rows: existing } = await db.query(
                'SELECT * FROM usuarios WHERE email = $1',
                [email]
            );

            if (existing.length > 0) {
                console.log('❌ [REGISTER] Usuario ya existe');
                return res.status(400).json({ message: 'El usuario ya existe' });
            }

            console.log('🔐 [REGISTER] Hasheando contraseña');
            const hashedPassword = await bcrypt.hash(password, 10);
            
            console.log('📦 [REGISTER] Insertando usuario');
            const { rows: newUser } = await db.query(
                'INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3) RETURNING id',
                [nombre, email, hashedPassword]
            );

            console.log('✅ [REGISTER] Usuario creado ID:', newUser[0].id);
            const token = jwt.sign({ userId: newUser[0].id }, JWT_SECRET, { expiresIn: '30d' });

            res.json({
                message: 'Usuario registrado',
                token,
                userId: newUser[0].id,
                nombre
            });

        } catch (err) {
            console.error('❌ [REGISTER] Error:', err);
            res.status(500).json({ message: err.message });
        }
    }
);
console.log('✅ Ruta /api/register configurada');

// ===================== VERIFICAR ADMIN =====================
app.get('/api/user/is-admin', async (req, res) => {
    console.log('👑 [IS-ADMIN] Ruta llamada');
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [IS-ADMIN] No autorizado - sin token');
        return res.json({ isAdmin: false });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('✅ [IS-ADMIN] Token válido para usuario:', decoded.userId);
        
        const { rows } = await db.query(
            'SELECT is_admin FROM usuarios WHERE id = $1',
            [decoded.userId]
        );

        if (rows.length > 0 && rows[0].is_admin) {
            console.log('✅ [IS-ADMIN] Usuario es admin');
            res.json({ isAdmin: true });
        } else {
            console.log('❌ [IS-ADMIN] Usuario no es admin');
            res.json({ isAdmin: false });
        }

    } catch (err) {
        console.error('❌ [IS-ADMIN] Error:', err);
        res.json({ isAdmin: false });
    }
});
console.log('✅ Ruta /api/user/is-admin configurada');

// ===================== LOGIN CON VALIDACIÓN =====================
app.post('/api/login',
    [
        body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
        body('password').notEmpty().withMessage('La contraseña es obligatoria')
    ],
    async (req, res) => {
        console.log('🔐 [LOGIN] Ruta llamada');
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('❌ [LOGIN] Errores de validación:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            console.log('🔍 [LOGIN] Buscando usuario:', email);
            const { rows } = await db.query(
                'SELECT * FROM usuarios WHERE email = $1',
                [email]
            );

            if (rows.length === 0) {
                console.log('❌ [LOGIN] Usuario no encontrado');
                return res.status(401).json({ message: 'Credenciales incorrectas' });
            }

            const user = rows[0];
            console.log('✅ [LOGIN] Usuario encontrado, verificando contraseña');
            const valid = await bcrypt.compare(password, user.password);

            if (!valid) {
                console.log('❌ [LOGIN] Contraseña incorrecta');
                return res.status(401).json({ message: 'Credenciales incorrectas' });
            }

            console.log('✅ [LOGIN] Login exitoso para usuario:', user.id);
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

            res.json({
                message: 'Login exitoso',
                token,
                userId: user.id,
                nombre: user.nombre
            });

        } catch (err) {
            console.error('❌ [LOGIN] Error:', err);
            res.status(500).json({ message: err.message });
        }
    }
);
console.log('✅ Ruta /api/login configurada');

// ===================== PERFIL DE USUARIO =====================
app.get('/api/users/me', async (req, res) => {
    console.log('👤 [PROFILE] Ruta llamada');
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [PROFILE] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('✅ [PROFILE] Token válido para usuario:', decoded.userId);
        
        const { rows } = await db.query(
            'SELECT id, nombre, email, fecha_creacion FROM usuarios WHERE id = $1',
            [decoded.userId]
        );

        if (rows.length === 0) {
            console.log('❌ [PROFILE] Usuario no encontrado');
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        console.log('✅ [PROFILE] Perfil enviado');
        res.json(rows[0]);

    } catch (err) {
        console.error('❌ [PROFILE] Error:', err);
        res.status(401).json({ message: 'Token inválido o expirado' });
    }
});
console.log('✅ Ruta /api/users/me configurada');

// ===================== ACTUALIZAR PERFIL =====================
app.put('/api/users/me', async (req, res) => {
    console.log('✏️ [UPDATE-PROFILE] Ruta llamada');
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [UPDATE-PROFILE] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('✅ [UPDATE-PROFILE] Token válido para usuario:', decoded.userId);
        
        const { nombre } = req.body;
        
        await db.query(
            'UPDATE usuarios SET nombre = $1 WHERE id = $2',
            [nombre, decoded.userId]
        );

        console.log('✅ [UPDATE-PROFILE] Perfil actualizado');
        res.json({ message: 'Perfil actualizado correctamente' });

    } catch (err) {
        console.error('❌ [UPDATE-PROFILE] Error:', err);
        res.status(500).json({ message: err.message });
    }
});
console.log('✅ Ruta PUT /api/users/me configurada');

// ===================== CAMBIAR CONTRASEÑA =====================
app.post('/api/users/change-password', async (req, res) => {
    console.log('🔑 [CHANGE-PASSWORD] Ruta llamada');
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [CHANGE-PASSWORD] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('✅ [CHANGE-PASSWORD] Token válido para usuario:', decoded.userId);
        
        const { currentPassword, newPassword } = req.body;

        const { rows } = await db.query(
            'SELECT password FROM usuarios WHERE id = $1',
            [decoded.userId]
        );

        if (rows.length === 0) {
            console.log('❌ [CHANGE-PASSWORD] Usuario no encontrado');
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const valid = await bcrypt.compare(currentPassword, rows[0].password);
        
        if (!valid) {
            console.log('❌ [CHANGE-PASSWORD] Contraseña actual incorrecta');
            return res.status(401).json({ message: 'Contraseña actual incorrecta' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query(
            'UPDATE usuarios SET password = $1 WHERE id = $2',
            [hashedPassword, decoded.userId]
        );

        console.log('✅ [CHANGE-PASSWORD] Contraseña actualizada');
        res.json({ message: 'Contraseña actualizada correctamente' });

    } catch (err) {
        console.error('❌ [CHANGE-PASSWORD] Error:', err);
        res.status(500).json({ message: err.message });
    }
});
console.log('✅ Ruta /api/users/change-password configurada');

// ===================== CONTACTO CON VALIDACIÓN =====================
app.post('/api/contact',
    [
        body('name').notEmpty().withMessage('El nombre es obligatorio').trim().escape(),
        body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
        body('subject').optional().trim().escape(),
        body('message').notEmpty().withMessage('El mensaje es obligatorio').trim().escape()
    ],
    async (req, res) => {
        console.log('📧 [CONTACT] Ruta llamada');
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('❌ [CONTACT] Errores de validación:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, subject, message } = req.body;

        try {
            console.log('📦 [CONTACT] Guardando mensaje en BD');
            await db.query(
                'INSERT INTO contact_messages (nombre, email, asunto, mensaje) VALUES ($1, $2, $3, $4)',
                [name, email, subject || 'Sin asunto', message]
            );
            console.log('✅ [CONTACT] Mensaje guardado en BD');

            console.log('📧 [CONTACT] Configurando transporte de email');
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            await transporter.verify();
            console.log('✅ [CONTACT] Conexión SMTP verificada');

            const mailOptions = {
    from: `"Formulario Web" <${process.env.EMAIL_USER}>`,
    to: 'guilleriveraa12@gmail.com',
    replyTo: email,
    subject: `📬 ${subject || 'Nuevo mensaje'} de ${name}`,
    html: `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    background-color: #f4f4f4;
                    padding: 20px;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    border-radius: 16px;
                    overflow: hidden;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                    animation: slideIn 0.5s ease-out;
                }
                @keyframes slideIn {
                    from {
                        opacity: 0;
                        transform: translateY(20px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                .header {
                    background: linear-gradient(135deg, #d81b60 0%, #c2185b 100%);
                    color: white;
                    padding: 30px 25px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    font-weight: 600;
                    letter-spacing: -0.5px;
                }
                .header p {
                    margin: 10px 0 0;
                    font-size: 16px;
                    opacity: 0.9;
                }
                .header i {
                    font-size: 40px;
                    margin-bottom: 15px;
                    display: block;
                }
                .content {
                    padding: 30px 25px;
                }
                .message-info {
                    background: #f8f9fa;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 25px;
                    border-left: 4px solid #d81b60;
                }
                .field {
                    margin-bottom: 20px;
                }
                .field:last-child {
                    margin-bottom: 0;
                }
                .label {
                    font-weight: 600;
                    color: #555;
                    font-size: 14px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 5px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .label i {
                    color: #d81b60;
                    width: 20px;
                }
                .value {
                    background: white;
                    padding: 15px;
                    border-radius: 10px;
                    color: #333;
                    font-size: 15px;
                    border: 1px solid #e0e0e0;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.02);
                }
                .message-box {
                    background: #fff3e0;
                    border-radius: 12px;
                    padding: 20px;
                    margin-top: 25px;
                }
                .message-box .label {
                    color: #e65100;
                }
                .message-box .value {
                    background: #ffffff;
                    border-color: #ffb74d;
                    white-space: pre-wrap;
                    font-style: italic;
                }
                .footer {
                    background: #f8f9fa;
                    padding: 25px;
                    text-align: center;
                    border-top: 1px solid #e0e0e0;
                }
                .footer p {
                    color: #666;
                    font-size: 14px;
                    margin: 5px 0;
                }
                .footer .social-links {
                    margin: 15px 0 10px;
                }
                .footer .social-links a {
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    width: 36px;
                    height: 36px;
                    background: white;
                    color: #d81b60;
                    border-radius: 50%;
                    margin: 0 5px;
                    text-decoration: none;
                    transition: all 0.3s ease;
                    border: 1px solid #e0e0e0;
                }
                .footer .social-links a:hover {
                    background: #d81b60;
                    color: white;
                    transform: translateY(-2px);
                }
                .footer .social-links i {
                    font-size: 16px;
                }
                .divider {
                    height: 2px;
                    background: linear-gradient(to right, transparent, #d81b60, transparent);
                    margin: 20px 0;
                }
                .badge {
                    display: inline-block;
                    background: #d81b60;
                    color: white;
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: 600;
                    letter-spacing: 0.5px;
                    text-transform: uppercase;
                }
                @media (max-width: 600px) {
                    .container {
                        border-radius: 12px;
                    }
                    .header {
                        padding: 25px 20px;
                    }
                    .header h1 {
                        font-size: 24px;
                    }
                    .content {
                        padding: 20px;
                    }
                    .message-info {
                        padding: 15px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <i class="fas fa-envelope-open-text"></i>
                    <h1>📬 Nuevo mensaje de contacto</h1>
                    <p>Has recibido un nuevo mensaje desde el formulario de contacto</p>
                </div>
                
                <div class="content">
                    <div class="badge" style="margin-bottom: 20px;">Información del remitente</div>
                    
                    <div class="message-info">
                        <div class="field">
                            <div class="label">
                                <i class="fas fa-user"></i>
                                Nombre:
                            </div>
                            <div class="value">${name}</div>
                        </div>
                        
                        <div class="field">
                            <div class="label">
                                <i class="fas fa-envelope"></i>
                                Email:
                            </div>
                            <div class="value">
                                <a href="mailto:${email}" style="color: #d81b60; text-decoration: none;">${email}</a>
                            </div>
                        </div>
                        
                        <div class="field">
                            <div class="label">
                                <i class="fas fa-tag"></i>
                                Asunto:
                            </div>
                            <div class="value">${subject || 'Sin asunto'}</div>
                        </div>
                        
                        <div class="field">
                            <div class="label">
                                <i class="fas fa-calendar"></i>
                                Fecha:
                            </div>
                            <div class="value">${new Date().toLocaleString('es-ES', {
                                year: 'numeric',
                                month: 'long',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit'
                            })}</div>
                        </div>
                    </div>

                    <div class="divider"></div>

                    <div class="badge" style="margin-bottom: 20px;">Mensaje</div>
                    
                    <div class="message-box">
                        <div class="field">
                            <div class="value">${message.replace(/\n/g, '<br>')}</div>
                        </div>
                    </div>

                    <div style="background: #f1f8e9; border-radius: 12px; padding: 15px; margin-top: 25px; border-left: 4px solid #4caf50;">
                        <div style="display: flex; align-items: center; gap: 10px; color: #2e7d32;">
                            <i class="fas fa-clock" style="font-size: 20px;"></i>
                            <span style="font-weight: 600;">Tiempo de respuesta estimado: 24-48 horas</span>
                        </div>
                    </div>
                </div>
                
                <div class="footer">
                    <div class="social-links">
                        <a href="https://www.facebook.com/SalamancaVivelaES" target="_blank">
                            <i class="fab fa-facebook-f"></i>
                        </a>
                        <a href="https://www.instagram.com/salamancavivela/" target="_blank">
                            <i class="fab fa-instagram"></i>
                        </a>
                        <a href="https://x.com/SalamancaVivela" target="_blank">
                            <i class="fab fa-twitter"></i>
                        </a>
                        <a href="https://www.tiktok.com/@salamancavivela" target="_blank">
                            <i class="fab fa-tiktok"></i>
                        </a>
                    </div>
                    <p style="font-weight: 600; color: #333;">© ${new Date().getFullYear()} Salamanca Vive la</p>
                    <p style="font-size: 12px;">Este mensaje fue enviado desde el formulario de contacto de tu tienda online.</p>
                </div>
            </div>
        </body>
        </html>
    `
};

            await transporter.sendMail(mailOptions);
            console.log('✅ [CONTACT] Email enviado');
            res.json({ message: "Mensaje enviado correctamente" });

        } catch (err) {
            console.error('❌ [CONTACT] Error:', err);
            res.status(500).json({ message: "Error al enviar el mensaje" });
        }
    }
);
console.log('✅ Ruta /api/contact configurada');

// ===================== CARRITO =====================
console.log('🛒 Configurando funciones de carrito...');

async function getOrCreateCart(usuarioId) {
    console.log(`🛒 [getOrCreateCart] Buscando carrito para usuario ${usuarioId}`);
    const { rows: carrito } = await db.query(
        'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
        [usuarioId]
    );
    
    if (carrito.length === 0) {
        console.log(`🛒 [getOrCreateCart] Creando nuevo carrito para usuario ${usuarioId}`);
        const { rows: newCart } = await db.query(
            'INSERT INTO carritos (usuario_id) VALUES ($1) RETURNING id',
            [usuarioId]
        );
        console.log(`✅ [getOrCreateCart] Carrito creado ID: ${newCart[0].id}`);
        return newCart[0].id;
    }
    
    console.log(`✅ [getOrCreateCart] Carrito existente ID: ${carrito[0].id}`);
    return carrito[0].id;
}

// Obtener carrito
app.get('/api/cart', async (req, res) => {
    console.log('🛒 [GET CART] Ruta llamada');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [GET CART] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [GET CART] Token válido para usuario:', usuarioId);

        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            console.log('ℹ️ [GET CART] Carrito vacío');
            return res.json({ items: [], subtotal: 0, shipping: 0, total: 0 });
        }

        const carritoId = carrito[0].id;
        console.log(`🛒 [GET CART] Carrito ID: ${carritoId}`);

        const { rows: items } = await db.query(
            `SELECT ci.cantidad, ci.precio_unitario, p.id as producto_id, p.nombre, p.imagen
             FROM cart_items ci
             JOIN productos p ON ci.producto_id = p.id
             WHERE ci.carrito_id = $1`,
            [carritoId]
        );

        console.log(`📦 [GET CART] Items encontrados: ${items.length}`);

        let subtotal = 0;
        const formattedItems = items.map(item => {
            const precio = parseFloat(item.precio_unitario);
            subtotal += precio * item.cantidad;
            return {
                id: item.producto_id,
                name: item.nombre,
                price: precio,
                quantity: item.cantidad,
                image: item.imagen || ''
            };
        });

        const shipping = subtotal > 50 ? 0 : 4.99;
        const total = subtotal + shipping;

        console.log(`💰 [GET CART] Subtotal: ${subtotal}, Envío: ${shipping}, Total: ${total}`);
        res.json({
            items: formattedItems,
            subtotal,
            shipping,
            total
        });

    } catch (err) {
        console.error('❌ [GET CART] Error:', err);
        res.status(500).json({ message: 'Error al obtener el carrito' });
    }
});
console.log('✅ Ruta GET /api/cart configurada');

// Añadir producto al carrito
app.post('/api/cart/add', async (req, res) => {
    console.log('➕ [CART ADD] Ruta llamada');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [CART ADD] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { productId, quantity = 1 } = req.body;
    console.log(`➕ [CART ADD] Producto: ${productId}, Cantidad: ${quantity}`);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [CART ADD] Token válido para usuario:', usuarioId);

        const { rows: product } = await db.query(
            'SELECT * FROM productos WHERE id = $1',
            [productId]
        );

        if (product.length === 0) {
            console.log('❌ [CART ADD] Producto no encontrado');
            return res.status(404).json({ message: 'Producto no encontrado' });
        }

        console.log(`✅ [CART ADD] Producto encontrado: ${product[0].nombre}`);

        let { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        let carritoId;
        if (carrito.length === 0) {
            const { rows: newCart } = await db.query(
                'INSERT INTO carritos (usuario_id) VALUES ($1) RETURNING id',
                [usuarioId]
            );
            carritoId = newCart[0].id;
            console.log(`🆕 [CART ADD] Nuevo carrito creado ID: ${carritoId}`);
        } else {
            carritoId = carrito[0].id;
            console.log(`✅ [CART ADD] Carrito existente ID: ${carritoId}`);
        }

        const { rows: existing } = await db.query(
            'SELECT id, cantidad FROM cart_items WHERE carrito_id = $1 AND producto_id = $2',
            [carritoId, productId]
        );

        if (existing.length > 0) {
            console.log(`📦 [CART ADD] Producto ya existe, actualizando cantidad`);
            await db.query(
                'UPDATE cart_items SET cantidad = cantidad + $1 WHERE id = $2',
                [quantity, existing[0].id]
            );
        } else {
            console.log(`📦 [CART ADD] Añadiendo nuevo producto al carrito`);
            await db.query(
                'INSERT INTO cart_items (carrito_id, producto_id, cantidad, precio_unitario) VALUES ($1, $2, $3, $4)',
                [carritoId, productId, quantity, product[0].precio]
            );
        }

        console.log('✅ [CART ADD] Producto añadido correctamente');
        res.json({ message: 'Producto añadido al carrito' });

    } catch (err) {
        console.error('❌ [CART ADD] Error:', err);
        res.status(500).json({ message: 'Error al añadir producto' });
    }
});
console.log('✅ Ruta POST /api/cart/add configurada');

// Actualizar cantidad
app.post('/api/cart/update', async (req, res) => {
    console.log('🔄 [CART UPDATE] Ruta llamada');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [CART UPDATE] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { productId, delta } = req.body;
    console.log(`🔄 [CART UPDATE] Producto: ${productId}, Delta: ${delta}`);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [CART UPDATE] Token válido para usuario:', usuarioId);

        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            console.log('❌ [CART UPDATE] Carrito no encontrado');
            return res.status(404).json({ message: 'Carrito no encontrado' });
        }

        const carritoId = carrito[0].id;

        if (delta > 0) {
            console.log('➕ [CART UPDATE] Incrementando cantidad');
            await db.query(
                'UPDATE cart_items SET cantidad = cantidad + $1 WHERE carrito_id = $2 AND producto_id = $3',
                [delta, carritoId, productId]
            );
        } else {
            console.log('➖ [CART UPDATE] Decrementando cantidad');
            await db.query(
                'UPDATE cart_items SET cantidad = cantidad + $1 WHERE carrito_id = $2 AND producto_id = $3 AND cantidad > $4',
                [delta, carritoId, productId, -delta]
            );
            
            await db.query(
                'DELETE FROM cart_items WHERE carrito_id = $1 AND producto_id = $2 AND cantidad <= 0',
                [carritoId, productId]
            );
            console.log('🗑️ [CART UPDATE] Producto eliminado (cantidad <= 0)');
        }

        console.log('✅ [CART UPDATE] Carrito actualizado');
        res.json({ message: 'Carrito actualizado' });

    } catch (err) {
        console.error('❌ [CART UPDATE] Error:', err);
        res.status(500).json({ message: 'Error al actualizar carrito' });
    }
});
console.log('✅ Ruta POST /api/cart/update configurada');

// Eliminar producto del carrito
app.delete('/api/cart/remove/:productId', async (req, res) => {
    console.log('🗑️ [CART REMOVE] Ruta llamada');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [CART REMOVE] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { productId } = req.params;
    console.log(`🗑️ [CART REMOVE] Producto: ${productId}`);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [CART REMOVE] Token válido para usuario:', usuarioId);

        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            console.log('❌ [CART REMOVE] Carrito no encontrado');
            return res.status(404).json({ message: 'Carrito no encontrado' });
        }

        await db.query(
            'DELETE FROM cart_items WHERE carrito_id = $1 AND producto_id = $2',
            [carrito[0].id, productId]
        );

        console.log('✅ [CART REMOVE] Producto eliminado');
        res.json({ message: 'Producto eliminado del carrito' });

    } catch (err) {
        console.error('❌ [CART REMOVE] Error:', err);
        res.status(500).json({ message: 'Error al eliminar producto' });
    }
});
console.log('✅ Ruta DELETE /api/cart/remove/:productId configurada');

// ===================== PRODUCTOS =====================
app.get('/api/productos', async (req, res) => {
    console.log('📦 [PRODUCTOS] Ruta llamada');
    const { categoria } = req.query;
    console.log(`📦 [PRODUCTOS] Categoría: ${categoria || 'todas'}`);
    
    try {
        let query = `
            SELECT p.*, c.nombre as categoria_nombre
            FROM productos p
            LEFT JOIN categorias c ON p.categoria_id = c.id
        `;
        let params = [];
        
        if (categoria) {
            query += ` WHERE c.nombre = $1`;
            params.push(categoria);
        }
        
        query += ` ORDER BY p.nombre ASC`;
        
        const { rows: productos } = await db.query(query, params);
        console.log(`✅ [PRODUCTOS] Encontrados: ${productos.length}`);
        res.json(productos);
        
    } catch (err) {
        console.error('❌ [PRODUCTOS] Error:', err);
        res.status(500).json({ message: 'Error al obtener productos' });
    }
});
console.log('✅ Ruta GET /api/productos configurada');

app.get('/api/productos/:id', async (req, res) => {
    const { id } = req.params;
    console.log(`📦 [PRODUCTO DETALLE] Ruta llamada para ID: ${id}`);
    
    try {
        const { rows: productos } = await db.query(
            `SELECT p.*, c.nombre as categoria_nombre
             FROM productos p
             LEFT JOIN categorias c ON p.categoria_id = c.id
             WHERE p.id = $1`,
            [id]
        );
        
        if (productos.length === 0) {
            console.log('❌ [PRODUCTO DETALLE] Producto no encontrado');
            return res.status(404).json({ message: 'Producto no encontrado' });
        }
        
        console.log('✅ [PRODUCTO DETALLE] Producto encontrado');
        res.json(productos[0]);
        
    } catch (err) {
        console.error('❌ [PRODUCTO DETALLE] Error:', err);
        res.status(500).json({ message: 'Error al obtener producto' });
    }
});
console.log('✅ Ruta GET /api/productos/:id configurada');

app.get('/api/categorias', async (req, res) => {
    console.log('📑 [CATEGORIAS] Ruta llamada');
    try {
        const { rows: categorias } = await db.query(
            'SELECT * FROM categorias ORDER BY nombre ASC'
        );
        console.log(`✅ [CATEGORIAS] Encontradas: ${categorias.length}`);
        res.json(categorias);
    } catch (err) {
        console.error('❌ [CATEGORIAS] Error:', err);
        res.status(500).json({ message: 'Error al obtener categorías' });
    }
});
console.log('✅ Ruta GET /api/categorias configurada');

// ===================== RESEÑAS DE PRODUCTOS (PÚBLICAS) =====================
console.log('⭐ Configurando rutas públicas de reseñas...');

// Middleware para verificar usuario (versión simple)
async function verificarUsuario(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuarioId = decoded.userId;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Token inválido' });
    }
}

// Obtener reseñas de un producto
app.get('/api/productos/:productoId/resenas', async (req, res) => {
    const { productoId } = req.params;
    console.log(`⭐ [GET RESENAS] Para producto ${productoId}`);

    try {
        const { rows: resenas } = await db.query(
            `SELECT r.*, u.nombre as usuario_nombre 
             FROM reseñas r
             JOIN usuarios u ON r.usuario_id = u.id
             WHERE r.producto_id = $1 AND r.estado = 'aprobada'
             ORDER BY r.fecha DESC`,
            [productoId]
        );

        console.log(`⭐ Reseñas encontradas: ${resenas.length}`);
        res.json(resenas);
    } catch (err) {
        console.error('❌ Error al obtener reseñas:', err);
        res.status(500).json({ message: 'Error al obtener reseñas' });
    }
});

// Verificar si el usuario puede reseñar un producto
app.get('/api/puede-resenar/:productoId', verificarUsuario, async (req, res) => {
    const { productoId } = req.params;
    const usuarioId = req.usuarioId;
    
    console.log(`⭐ [PUEDE RESEÑAR] Usuario ${usuarioId}, Producto ${productoId}`);

    try {
        // Verificar si el usuario compró el producto
        const { rows: compras } = await db.query(
            `SELECT oi.id FROM order_items oi
             JOIN pedidos p ON oi.pedido_id = p.id
             WHERE p.usuario_id = $1 
               AND oi.producto_id = $2
               AND p.estado IN ('entregado', 'pagado', 'enviado')
             LIMIT 1`,
            [usuarioId, productoId]
        );

        if (compras.length === 0) {
            return res.json({ puedeResenar: false, mensaje: 'Debes comprar el producto primero' });
        }

        // Verificar si ya reseñó
        const { rows: yaResenado } = await db.query(
            'SELECT id FROM reseñas WHERE usuario_id = $1 AND producto_id = $2',
            [usuarioId, productoId]
        );

        res.json({ 
            puedeResenar: yaResenado.length === 0,
            mensaje: yaResenado.length > 0 ? 'Ya has reseñado este producto' : 'Puedes reseñar'
        });

    } catch (err) {
        console.error('❌ Error al verificar:', err);
        res.status(500).json({ message: 'Error al verificar' });
    }
});

// Enviar una reseña
app.post('/api/resenas', verificarUsuario, async (req, res) => {
    const { productoId, puntuacion, comentario, titulo } = req.body;
    const usuarioId = req.usuarioId;

    console.log(`⭐ [NUEVA RESEÑA] Usuario ${usuarioId}, Producto ${productoId}`);
    console.log('📝 Datos recibidos:', { productoId, puntuacion, comentario, titulo });

    // Validaciones básicas
    if (!productoId || !puntuacion || puntuacion < 1 || puntuacion > 5) {
        return res.status(400).json({ message: 'Datos inválidos: producto y puntuación (1-5) son obligatorios' });
    }

    if (!comentario || comentario.trim().length === 0) {
        return res.status(400).json({ message: 'El comentario es obligatorio' });
    }

    try {
        // Verificar que el usuario compró el producto
        const { rows: compras } = await db.query(
            `SELECT p.id, oi.pedido_id 
             FROM pedidos p
             JOIN order_items oi ON p.id = oi.pedido_id
             WHERE p.usuario_id = $1 AND oi.producto_id = $2
               AND p.estado IN ('entregado', 'pagado', 'enviado')
             ORDER BY p.fecha DESC
             LIMIT 1`,
            [usuarioId, productoId]
        );

        if (compras.length === 0) {
            return res.status(403).json({ message: 'Debes comprar el producto para reseñarlo' });
        }

        const pedidoId = compras[0].pedido_id;

        // Verificar que no haya reseñado ya
        const { rows: existente } = await db.query(
            'SELECT id FROM reseñas WHERE usuario_id = $1 AND producto_id = $2',
            [usuarioId, productoId]
        );

        if (existente.length > 0) {
            return res.status(400).json({ message: 'Ya has reseñado este producto' });
        }

        // Insertar reseña con los campos CORRECTOS de tu tabla
        const { rows: nuevaResena } = await db.query(
            `INSERT INTO reseñas 
             (usuario_id, producto_id, pedido_id, titulo, comentario, calificacion, fecha, estado)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), 'pendiente')
             RETURNING id`,
            [usuarioId, productoId, pedidoId, titulo || null, comentario, puntuacion]
        );

        console.log(`✅ Reseña creada ID: ${nuevaResena[0].id}`);
        res.json({ 
            message: 'Reseña enviada correctamente. Pendiente de aprobación.',
            id: nuevaResena[0].id 
        });

    } catch (err) {
        console.error('❌ Error al guardar reseña:', err);
        console.error('❌ Detalle:', err.message);
        res.status(500).json({ 
            message: 'Error al guardar la reseña',
            error: err.message 
        });
    }
});

// ===================== CUPONES DE DESCUENTO =====================
app.post('/api/cupones/validar', async (req, res) => {
    console.log('🎫 [CUPON VALIDAR] Ruta llamada');
    const { codigo, subtotal, usuarioId } = req.body;
    console.log(`🎫 [CUPON VALIDAR] Código: ${codigo}, Subtotal: ${subtotal}`);
    
    if (!codigo) {
        console.log('❌ [CUPON VALIDAR] Código requerido');
        return res.status(400).json({ message: 'Código de cupón requerido' });
    }

    try {
        const { rows: cupones } = await db.query(
            `SELECT * FROM cupones 
             WHERE codigo = $1 AND activo = TRUE 
             AND (fecha_fin IS NULL OR fecha_fin >= NOW())`,
            [codigo]
        );

        if (cupones.length === 0) {
            console.log('❌ [CUPON VALIDAR] Cupón no válido');
            return res.json({ valido: false, message: 'Cupón no válido o expirado' });
        }

        const cupon = cupones[0];
        console.log(`✅ [CUPON VALIDAR] Cupón encontrado ID: ${cupon.id}`);

        if (subtotal && cupon.monto_minimo > subtotal) {
            console.log(`❌ [CUPON VALIDAR] Monto mínimo no alcanzado: ${cupon.monto_minimo}`);
            return res.json({ 
                valido: false, 
                message: `Monto mínimo de ${parseFloat(cupon.monto_minimo).toFixed(2)}€` 
            });
        }

        if (cupon.usos_actuales >= cupon.uso_maximo) {
            console.log('❌ [CUPON VALIDAR] Cupón agotado');
            return res.json({ valido: false, message: 'Cupón agotado' });
        }

        if (usuarioId) {
            const { rows: usado } = await db.query(
                'SELECT * FROM cupones_usados WHERE cupon_id = $1 AND usuario_id = $2',
                [cupon.id, usuarioId]
            );

            if (usado.length >= cupon.uso_por_usuario) {
                console.log('❌ [CUPON VALIDAR] Cupón ya usado por este usuario');
                return res.json({ valido: false, message: 'Ya has usado este cupón' });
            }
        }

        let descuento = 0;
        if (cupon.tipo_descuento === 'porcentaje') {
            descuento = (parseFloat(subtotal) * parseFloat(cupon.valor_descuento) / 100);
        } else {
            descuento = parseFloat(cupon.valor_descuento);
        }

        console.log(`✅ [CUPON VALIDAR] Cupón válido, descuento: ${descuento}`);
        res.json({
            valido: true,
            cupon: {
                id: cupon.id,
                codigo: cupon.codigo,
                tipo: cupon.tipo_descuento,
                valor: parseFloat(cupon.valor_descuento),
                descuento_calculado: descuento
            },
            message: 'Cupón válido'
        });

    } catch (err) {
        console.error('❌ [CUPON VALIDAR] Error:', err);
        res.status(500).json({ message: 'Error al validar cupón' });
    }
});
console.log('✅ Ruta POST /api/cupones/validar configurada');

// ===================== PAGOS CON STRIPE =====================
app.post('/api/create-checkout-session',
    [
        body('cuponId').optional({ nullable: true }).isInt().withMessage('ID de cupón inválido'),
        body('direccion').optional().isObject().withMessage('Dirección inválida'),
        body('direccion.nombre').optional().trim().escape(),
        body('direccion.calle').optional().trim().escape(),
        body('direccion.piso').optional().trim().escape(),
        body('direccion.ciudad').optional().trim().escape(),
        body('direccion.codigo_postal').optional().trim().escape(),
        body('direccion.pais').optional().trim().escape()
    ],
    async (req, res) => {
        console.log('💳 [CHECKOUT] Ruta llamada');
        
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log('❌ [CHECKOUT] Errores de validación:', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }
        
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('❌ [CHECKOUT] No autorizado - sin token');
            return res.status(401).json({ message: 'No autorizado' });
        }

        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            const usuarioId = decoded.userId;
            console.log('✅ [CHECKOUT] Token válido para usuario:', usuarioId);

            const direccionData = req.body.direccion;
            let direccionEnvio = null;
            let direccionDetalles = null;

            if (direccionData) {
                const partesDireccion = [
                    direccionData.calle || '',
                    direccionData.piso || '',
                    direccionData.ciudad || '',
                    direccionData.codigo_postal || '',
                    direccionData.pais || ''
                ].filter(Boolean);
                
                direccionEnvio = partesDireccion.join(', ');
                direccionDetalles = JSON.stringify(direccionData);
                console.log('📍 [CHECKOUT] Dirección:', direccionEnvio);
            }

            const { rows: carrito } = await db.query(
                'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
                [usuarioId]
            );

            if (carrito.length === 0) {
                console.log('❌ [CHECKOUT] Carrito vacío');
                return res.status(404).json({ message: 'Carrito vacío' });
            }

            const carritoId = carrito[0].id;
            console.log(`✅ [CHECKOUT] Carrito ID: ${carritoId}`);

            const { rows: items } = await db.query(
                `SELECT ci.cantidad, ci.precio_unitario, p.id as producto_id, p.nombre
                 FROM cart_items ci
                 JOIN productos p ON ci.producto_id = p.id
                 WHERE ci.carrito_id = $1`,
                [carritoId]
            );

            if (items.length === 0) {
                console.log('❌ [CHECKOUT] Carrito vacío');
                return res.status(404).json({ message: 'Carrito vacío' });
            }

            console.log(`📦 [CHECKOUT] Items en carrito: ${items.length}`);

            let subtotal = 0;
            items.forEach(item => {
                const precio = parseFloat(item.precio_unitario) || 0;
                const cantidad = parseInt(item.cantidad) || 0;
                subtotal += precio * cantidad;
            });

            const shipping = subtotal > 50 ? 0 : 4.99;
            console.log(`💰 [CHECKOUT] Subtotal: ${subtotal.toFixed(2)}€, Envío: ${shipping.toFixed(2)}€`);

            // ===== NUEVO: Cálculo mejorado de descuentos =====
            let descuento = 0;
            let cuponId = null;
            let cuponAplicado = null;

            if (req.body.cuponId) {
                console.log(`🎫 [CHECKOUT] Verificando cupón ID: ${req.body.cuponId}`);
                const { rows: cupones } = await db.query(
                    'SELECT * FROM cupones WHERE id = $1 AND activo = TRUE AND (fecha_fin IS NULL OR fecha_fin >= NOW())',
                    [req.body.cuponId]
                );
                
                if (cupones.length > 0) {
                    const cupon = cupones[0];
                    console.log(`🎫 Cupón encontrado: ${cupon.codigo}, Tipo: ${cupon.tipo_descuento}, Valor: ${cupon.valor_descuento}`);
                    
                    // Verificar monto mínimo
                    if (!cupon.monto_minimo || subtotal >= parseFloat(cupon.monto_minimo)) {
                        cuponId = cupon.id;
                        cuponAplicado = cupon;
                        
                        if (cupon.tipo_descuento === 'porcentaje') {
                            descuento = (subtotal * parseFloat(cupon.valor_descuento)) / 100;
                            console.log(`💰 Descuento porcentaje ${cupon.valor_descuento}%: ${descuento.toFixed(2)}€`);
                        } else {
                            descuento = parseFloat(cupon.valor_descuento);
                            console.log(`💰 Descuento fijo: ${descuento.toFixed(2)}€`);
                        }
                        
                        // No permitir descuento mayor que el subtotal
                        if (descuento > subtotal) {
                            descuento = subtotal;
                            console.log(`💰 Descuento ajustado al subtotal: ${descuento.toFixed(2)}€`);
                        }
                    } else {
                        console.log(`⚠️ Monto mínimo no alcanzado: ${cupon.monto_minimo}€ > ${subtotal.toFixed(2)}€`);
                    }
                } else {
                    console.log(`⚠️ Cupón no válido o expirado ID: ${req.body.cuponId}`);
                }
            }

            const subtotalConDescuento = subtotal - descuento;
            const totalFinal = Math.max(0, subtotalConDescuento + shipping);
            console.log(`💰 [CHECKOUT] Descuento: ${descuento.toFixed(2)}€, Subtotal con descuento: ${subtotalConDescuento.toFixed(2)}€, Total final: ${totalFinal.toFixed(2)}€`);

           // ===== Construir line items (SIN LÍNEA DE DESCUENTO NEGATIVA) =====
let lineItems = items.map(item => ({
    price_data: {
        currency: 'eur',
        product_data: { 
            name: item.nombre.substring(0, 100)
        },
        unit_amount: Math.round(parseFloat(item.precio_unitario) * 100),
    },
    quantity: Math.min(parseInt(item.cantidad) || 1, 99),
}));

// Añadir gastos de envío si corresponde
if (shipping > 0) {
    lineItems.push({
        price_data: {
            currency: 'eur',
            product_data: { name: 'Gastos de envío' },
            unit_amount: Math.round(shipping * 100),
        },
        quantity: 1,
    });
}

// NO AÑADIR LÍNEA DE DESCUENTO NEGATIVA (Stripe no lo permite)

if (shipping > 0) {
    lineItems.push({
        price_data: {
            currency: 'eur',
            product_data: { name: 'Gastos de envío' },
            unit_amount: Math.round(shipping * 100),
        },
        quantity: 1,
    });
}

            if (shipping > 0) {
                lineItems.push({
                    price_data: {
                        currency: 'eur',
                        product_data: { name: 'Gastos de envío' },
                        unit_amount: Math.round(shipping * 100),
                    },
                    quantity: 1,
                });
            }

            // ===== NUEVO: Metadatos enriquecidos =====
            let sessionParams = {
                payment_method_types: ['card'],
                line_items: lineItems,
                mode: 'payment',
                success_url: `${process.env.BASE_URL}/pedido-exitoso.html?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.BASE_URL}/carrito.html?cancelado=true`,
                shipping_address_collection: { allowed_countries: ['ES'] },
                metadata: {
                    usuarioId: String(usuarioId),
                    carritoId: String(carritoId),
                    subtotal: subtotal.toFixed(2),
                    descuento: descuento.toFixed(2),
                    descuento_tipo: cuponAplicado?.tipo_descuento || '',
                    descuento_valor: cuponAplicado?.valor_descuento?.toString() || '',
                    cupon_codigo: cuponAplicado?.codigo || '',
                    subtotal_con_descuento: subtotalConDescuento.toFixed(2),
                    shipping: shipping.toFixed(2),
                    total: totalFinal.toFixed(2),
                    cuponId: cuponId ? String(cuponId) : '',
                    direccion_nombre: direccionData?.nombre || '',
                    direccion_calle: direccionData?.calle || '',
                    direccion_piso: direccionData?.piso || '',
                    direccion_ciudad: direccionData?.ciudad || '',
                    direccion_cp: direccionData?.codigo_postal || '',
                    direccion_pais: direccionData?.pais || ''
                },
            };

            const session = await stripe.checkout.sessions.create(sessionParams);
            console.log('✅ [CHECKOUT] Sesión de Stripe creada:', session.id);
            
            res.json({ id: session.id, url: session.url });

        } catch (err) {
            console.error('❌ [CHECKOUT] Error:', err);
            const errorMessage = process.env.NODE_ENV === 'production' 
                ? 'Error al procesar el pago' 
                : err.message;
            res.status(500).json({ message: errorMessage });
        }
    }
);
console.log('✅ Ruta POST /api/create-checkout-session configurada');

// ===================== PEDIDOS =====================
console.log('📦 Configurando rutas de pedidos...');

// 🔴 PRIMERO: RUTA ESPECÍFICA DE DEVOLUCIONES
app.get('/api/orders/eligible-for-return', async (req, res) => {
    console.log('\n========== DEVOLUCIONES ==========');
    console.log('📦 [ELIGIBLE-RETURN] Ruta llamada');
    
    const authHeader = req.headers.authorization;
    console.log('Auth header existe:', !!authHeader);
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [ELIGIBLE-RETURN] No autorizado - header inválido');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    console.log('Token recibido (primeros 20 chars):', token.substring(0, 20) + '...');

    try {
        console.log('🔐 [ELIGIBLE-RETURN] Verificando token...');
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [ELIGIBLE-RETURN] Token válido. Usuario ID:', usuarioId);

        console.log('📊 [ELIGIBLE-RETURN] Consultando pedidos elegibles...');
        const { rows: pedidos } = await db.query(
            `SELECT 
                id,
                TO_CHAR(fecha, 'DD/MM/YYYY') as date,
                total,
                estado as status
             FROM pedidos
             WHERE usuario_id = $1 
               AND estado = 'entregado'
               AND fecha >= NOW() - INTERVAL '30 days'
             ORDER BY fecha DESC`,
            [usuarioId]
        );

        console.log(`📦 [ELIGIBLE-RETURN] Pedidos encontrados: ${pedidos.length}`);
        
        if (pedidos.length === 0) {
            console.log('ℹ️ [ELIGIBLE-RETURN] No hay pedidos elegibles');
            return res.json([]);
        }

        const pedidosConItems = await Promise.all(pedidos.map(async (pedido) => {
            console.log(`🔍 [ELIGIBLE-RETURN] Buscando items para pedido ${pedido.id}...`);
            const { rows: items } = await db.query(
                `SELECT 
                    oi.producto_id as id,
                    p.nombre as name,
                    oi.cantidad as quantity,
                    oi.precio as price
                 FROM order_items oi
                 JOIN productos p ON oi.producto_id = p.id
                 WHERE oi.pedido_id = $1`,
                [pedido.id]
            );
            
            console.log(`   → ${items.length} items encontrados`);
            return { ...pedido, items };
        }));

        console.log('✅ [ELIGIBLE-RETURN] Respuesta enviada correctamente');
        res.json(pedidosConItems);

    } catch (err) {
        console.error('❌ [ELIGIBLE-RETURN] ERROR:');
        console.error('   Mensaje:', err.message);
        console.error('   Stack:', err.stack);
        res.status(500).json({ message: 'Error al obtener pedidos: ' + err.message });
    }
});
console.log('✅ Ruta GET /api/orders/eligible-for-return configurada');

// 🟡 SEGUNDO: RUTA DE MIS PEDIDOS
app.get('/api/orders/my-orders', async (req, res) => {
    console.log('📦 [MY-ORDERS] Ruta llamada');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [MY-ORDERS] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [MY-ORDERS] Token válido para usuario:', usuarioId);

        const { rows: pedidos } = await db.query(
            `SELECT 
                id,
                fecha as date,
                total,
                estado as status,
                tracking_number,
                tracking_company
             FROM pedidos
             WHERE usuario_id = $1
             ORDER BY fecha DESC`,
            [usuarioId]
        );

        console.log(`✅ [MY-ORDERS] Pedidos encontrados: ${pedidos.length}`);
        res.json(pedidos);

    } catch (err) {
        console.error('❌ [MY-ORDERS] Error:', err);
        res.status(500).json({ message: 'Error al obtener pedidos' });
    }
});
console.log('✅ Ruta GET /api/orders/my-orders configurada');

// 🟢 TERCERO: RUTAS CON PARÁMETROS
app.get('/api/orders/:orderId', async (req, res) => {
    const { orderId } = req.params;
    console.log(`📦 [ORDER DETAIL] Ruta llamada para pedido: ${orderId}`);
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [ORDER DETAIL] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [ORDER DETAIL] Token válido para usuario:', usuarioId);

        const { rows: pedidos } = await db.query(
            'SELECT * FROM pedidos WHERE id = $1 AND usuario_id = $2',
            [orderId, usuarioId]
        );

        if (pedidos.length === 0) {
            console.log('❌ [ORDER DETAIL] Pedido no encontrado');
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        console.log('✅ [ORDER DETAIL] Pedido encontrado');
        res.json(pedidos[0]);

    } catch (err) {
        console.error('❌ [ORDER DETAIL] Error:', err);
        res.status(500).json({ message: 'Error al obtener pedido' });
    }
});
console.log('✅ Ruta GET /api/orders/:orderId configurada');

app.get('/api/orders/:orderId/items', async (req, res) => {
    const { orderId } = req.params;
    console.log(`📦 [ORDER ITEMS] Ruta llamada para pedido: ${orderId}`);
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [ORDER ITEMS] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ [ORDER ITEMS] Token válido para usuario:', usuarioId);

        const { rows: pedido } = await db.query(
            'SELECT id FROM pedidos WHERE id = $1 AND usuario_id = $2',
            [orderId, usuarioId]
        );

        if (pedido.length === 0) {
            console.log('❌ [ORDER ITEMS] Pedido no encontrado');
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const { rows: items } = await db.query(
            `SELECT 
                oi.id,
                oi.producto_id,
                p.nombre,
                p.imagen,
                oi.cantidad,
                oi.precio
             FROM order_items oi
             JOIN productos p ON oi.producto_id = p.id
             WHERE oi.pedido_id = $1`,
            [orderId]
        );

        console.log(`✅ [ORDER ITEMS] Items encontrados: ${items.length}`);
        res.json(items);

    } catch (err) {
        console.error('❌ [ORDER ITEMS] Error:', err);
        res.status(500).json({ message: 'Error al obtener items' });
    }
});
console.log('✅ Ruta GET /api/orders/:orderId/items configurada');


// ===================== ADMIN - RUTAS PARA EL PANEL =====================
console.log('👑 Configurando rutas de administración...');

async function verificarAdmin(req, res, next) {
    console.log('🔐 [VERIFICAR ADMIN] Verificando permisos de admin');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ [VERIFICAR ADMIN] No autorizado - sin token');
        return res.status(401).json({ message: 'No autorizado' });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { rows } = await db.query('SELECT is_admin FROM usuarios WHERE id = $1', [decoded.userId]);
        
        if (!rows[0]?.is_admin) {
            console.log('❌ [VERIFICAR ADMIN] Acceso denegado - no es admin');
            return res.status(403).json({ message: 'Acceso denegado' });
        }
        
        console.log('✅ [VERIFICAR ADMIN] Admin verificado');
        req.usuarioId = decoded.userId;
        next();
    } catch (err) {
        console.error('❌ [VERIFICAR ADMIN] Error:', err);
        return res.status(401).json({ message: 'Token inválido' });
    }
}

// ===================== VALIDADORES PARA ADMIN =====================
const productValidator = [
    body('nombre').notEmpty().trim().escape(),
    body('descripcion').optional().trim().escape(),
    body('precio').isFloat({ min: 0 }),
    body('categoria_id').isInt(),
    body('imagen').optional().isURL()
];

const couponValidator = [
    body('codigo').notEmpty().trim().escape().toUpperCase(),
    body('descripcion').optional().trim().escape(),
    body('tipo_descuento').isIn(['porcentaje', 'fijo']),
    body('valor_descuento').isFloat({ min: 0 }),
    body('monto_minimo').optional().isFloat({ min: 0 }),
    body('uso_maximo').optional().isInt({ min: 1 })
];

const orderStatusValidator = [
    body('estado').isIn(['pendiente', 'procesando', 'enviado', 'entregado', 'cancelado'])
];

// ===================== RUTAS ADMIN =====================
app.get('/api/admin/pedidos', verificarAdmin, async (req, res) => {
    console.log('👑 [ADMIN PEDIDOS] Ruta llamada');
    try {
        const { rows: pedidos } = await db.query(
            `SELECT p.*, u.nombre as cliente_nombre, u.email as cliente_email
             FROM pedidos p
             JOIN usuarios u ON p.usuario_id = u.id
             ORDER BY p.fecha DESC`
        );
        console.log(`✅ [ADMIN PEDIDOS] Pedidos encontrados: ${pedidos.length}`);
        res.json(pedidos);
    } catch (err) {
        console.error('❌ [ADMIN PEDIDOS] Error:', err);
        res.status(500).json({ message: 'Error al obtener pedidos' });
    }
});
console.log('✅ Ruta GET /api/admin/pedidos configurada');

app.put('/api/admin/pedidos/:id', verificarAdmin, orderStatusValidator, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN PEDIDOS UPDATE] Ruta llamada para pedido: ${id}`);
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('❌ [ADMIN PEDIDOS UPDATE] Errores de validación:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { estado } = req.body;
    console.log(`📦 [ADMIN PEDIDOS UPDATE] Nuevo estado: ${estado}`);

    try {
        const { rowCount } = await db.query(
            'UPDATE pedidos SET estado = $1 WHERE id = $2',
            [estado, id]
        );

        if (rowCount === 0) {
            console.log('❌ [ADMIN PEDIDOS UPDATE] Pedido no encontrado');
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        console.log('✅ [ADMIN PEDIDOS UPDATE] Estado actualizado');
        res.json({ message: 'Estado actualizado' });
    } catch (err) {
        console.error('❌ [ADMIN PEDIDOS UPDATE] Error:', err);
        res.status(500).json({ message: 'Error al actualizar' });
    }
});
console.log('✅ Ruta PUT /api/admin/pedidos/:id configurada');

app.get('/api/admin/ultimos-pedidos', verificarAdmin, async (req, res) => {
    console.log('👑 [ADMIN ULTIMOS PEDIDOS] Ruta llamada');
    const limite = req.query.limite ? parseInt(req.query.limite) : 5;
    if (isNaN(limite) || limite <= 0 || limite > 100) {
        console.log('❌ [ADMIN ULTIMOS PEDIDOS] Límite inválido:', limite);
        return res.status(400).json({ message: 'Límite inválido' });
    }
    
    try {
        const { rows: pedidos } = await db.query(
            `SELECT p.*, u.nombre as cliente_nombre
             FROM pedidos p
             JOIN usuarios u ON p.usuario_id = u.id
             ORDER BY p.fecha DESC
             LIMIT $1`,
            [limite]
        );
        console.log(`✅ [ADMIN ULTIMOS PEDIDOS] Pedidos encontrados: ${pedidos.length}`);
        res.json(pedidos);
    } catch (err) {
        console.error('❌ [ADMIN ULTIMOS PEDIDOS] Error:', err);
        res.status(500).json({ message: 'Error al obtener pedidos' });
    }
});
console.log('✅ Ruta GET /api/admin/ultimos-pedidos configurada');

app.get('/api/admin/cupones', verificarAdmin, async (req, res) => {
    console.log('👑 [ADMIN CUPONES] Ruta llamada');
    try {
        const { rows: cupones } = await db.query('SELECT * FROM cupones ORDER BY created_at DESC');
        console.log(`✅ [ADMIN CUPONES] Cupones encontrados: ${cupones.length}`);
        res.json(cupones);
    } catch (err) {
        console.error('❌ [ADMIN CUPONES] Error:', err);
        res.status(500).json({ message: 'Error al obtener cupones' });
    }
});
console.log('✅ Ruta GET /api/admin/cupones configurada');

app.post('/api/admin/cupones', verificarAdmin, couponValidator, async (req, res) => {
    console.log('👑 [ADMIN CUPONES CREATE] Ruta llamada');
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('❌ [ADMIN CUPONES CREATE] Errores de validación:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { codigo, descripcion, tipo_descuento, valor_descuento, monto_minimo, fecha_fin, uso_maximo } = req.body;
    console.log(`🎫 [ADMIN CUPONES CREATE] Creando cupón: ${codigo}`);

    try {
        const { rows: newCupon } = await db.query(
            `INSERT INTO cupones 
             (codigo, descripcion, tipo_descuento, valor_descuento, monto_minimo, fecha_fin, uso_maximo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
            [codigo, descripcion, tipo_descuento, valor_descuento, monto_minimo || 0, fecha_fin || null, uso_maximo || 1]
        );

        console.log(`✅ [ADMIN CUPONES CREATE] Cupón creado ID: ${newCupon[0].id}`);
        res.json({ message: 'Cupón creado', id: newCupon[0].id });
    } catch (err) {
        console.error('❌ [ADMIN CUPONES CREATE] Error:', err);
        res.status(500).json({ message: 'Error al crear cupón' });
    }
});
console.log('✅ Ruta POST /api/admin/cupones configurada');

app.put('/api/admin/cupones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN CUPONES UPDATE] Ruta llamada para cupón: ${id}`);
    
    const { activo } = req.body;

    if (typeof activo !== 'boolean') {
        console.log('❌ [ADMIN CUPONES UPDATE] activo debe ser booleano');
        return res.status(400).json({ message: 'activo debe ser booleano' });
    }

    try {
        await db.query('UPDATE cupones SET activo = $1 WHERE id = $2', [activo, id]);
        console.log('✅ [ADMIN CUPONES UPDATE] Cupón actualizado');
        res.json({ message: 'Cupón actualizado' });
    } catch (err) {
        console.error('❌ [ADMIN CUPONES UPDATE] Error:', err);
        res.status(500).json({ message: 'Error al actualizar' });
    }
});
console.log('✅ Ruta PUT /api/admin/cupones/:id configurada');

app.delete('/api/admin/cupones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN CUPONES DELETE] Ruta llamada para cupón: ${id}`);

    if (isNaN(parseInt(id))) {
        console.log('❌ [ADMIN CUPONES DELETE] ID inválido');
        return res.status(400).json({ message: 'ID inválido' });
    }

    try {
        await db.query('DELETE FROM cupones WHERE id = $1', [id]);
        console.log('✅ [ADMIN CUPONES DELETE] Cupón eliminado');
        res.json({ message: 'Cupón eliminado' });
    } catch (err) {
        console.error('❌ [ADMIN CUPONES DELETE] Error:', err);
        res.status(500).json({ message: 'Error al eliminar' });
    }
});
console.log('✅ Ruta DELETE /api/admin/cupones/:id configurada');

app.post('/api/admin/productos', verificarAdmin, productValidator, async (req, res) => {
    console.log('👑 [ADMIN PRODUCTOS CREATE] Ruta llamada');
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('❌ [ADMIN PRODUCTOS CREATE] Errores de validación:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { nombre, descripcion, precio, imagen, categoria_id } = req.body;
    console.log(`📦 [ADMIN PRODUCTOS CREATE] Creando producto: ${nombre}`);

    try {
        const { rows: newProduct } = await db.query(
            'INSERT INTO productos (nombre, descripcion, precio, imagen, categoria_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [nombre, descripcion, precio, imagen, categoria_id]
        );

        console.log(`✅ [ADMIN PRODUCTOS CREATE] Producto creado ID: ${newProduct[0].id}`);
        res.json({ message: 'Producto creado', id: newProduct[0].id });
    } catch (err) {
        console.error('❌ [ADMIN PRODUCTOS CREATE] Error:', err);
        res.status(500).json({ message: 'Error al crear producto' });
    }
});
console.log('✅ Ruta POST /api/admin/productos configurada');

app.put('/api/admin/productos/:id', verificarAdmin, productValidator, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN PRODUCTOS UPDATE] Ruta llamada para producto: ${id}`);
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('❌ [ADMIN PRODUCTOS UPDATE] Errores de validación:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { nombre, descripcion, precio, imagen, categoria_id } = req.body;

    try {
        await db.query(
            'UPDATE productos SET nombre = $1, descripcion = $2, precio = $3, imagen = $4, categoria_id = $5 WHERE id = $6',
            [nombre, descripcion, precio, imagen, categoria_id, id]
        );
        console.log('✅ [ADMIN PRODUCTOS UPDATE] Producto actualizado');
        res.json({ message: 'Producto actualizado' });
    } catch (err) {
        console.error('❌ [ADMIN PRODUCTOS UPDATE] Error:', err);
        res.status(500).json({ message: 'Error al actualizar producto' });
    }
});
console.log('✅ Ruta PUT /api/admin/productos/:id configurada');

app.delete('/api/admin/productos/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN PRODUCTOS DELETE] Ruta llamada para producto: ${id}`);

    try {
        await db.query('DELETE FROM productos WHERE id = $1', [id]);
        console.log('✅ [ADMIN PRODUCTOS DELETE] Producto eliminado');
        res.json({ message: 'Producto eliminado' });
    } catch (err) {
        console.error('❌ [ADMIN PRODUCTOS DELETE] Error:', err);
        res.status(500).json({ message: 'Error al eliminar producto' });
    }
});
console.log('✅ Ruta DELETE /api/admin/productos/:id configurada');

// ===================== ADMIN - DEVOLUCIONES =====================
app.get('/api/admin/devoluciones', verificarAdmin, async (req, res) => {
    console.log('👑 [ADMIN DEVOLUCIONES] Ruta llamada');
    try {
        const { rows: devoluciones } = await db.query(
            `SELECT d.*, u.nombre as cliente_nombre, u.email as cliente_email, p.total as pedido_total
             FROM devoluciones d
             JOIN pedidos p ON d.pedido_id = p.id
             JOIN usuarios u ON p.usuario_id = u.id
             ORDER BY d.fecha DESC`
        );
        console.log(`✅ [ADMIN DEVOLUCIONES] Devoluciones encontradas: ${devoluciones.length}`);
        res.json(devoluciones);
    } catch (err) {
        console.error('❌ [ADMIN DEVOLUCIONES] Error:', err);
        res.status(500).json({ message: 'Error al obtener devoluciones' });
    }
});
console.log('✅ Ruta GET /api/admin/devoluciones configurada');

app.put('/api/admin/devoluciones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN DEVOLUCIONES UPDATE] Ruta llamada para devolución: ${id}`);
    
    const { estado } = req.body;

    const estadosValidos = ['pendiente', 'aprobada', 'rechazada', 'completada'];
    if (!estadosValidos.includes(estado)) {
        console.log('❌ [ADMIN DEVOLUCIONES UPDATE] Estado no válido:', estado);
        return res.status(400).json({ message: 'Estado no válido' });
    }

    try {
        await db.query(
            'UPDATE devoluciones SET estado = $1 WHERE id = $2',
            [estado, id]
        );
        console.log('✅ [ADMIN DEVOLUCIONES UPDATE] Estado actualizado');
        res.json({ message: 'Estado actualizado' });
    } catch (err) {
        console.error('❌ [ADMIN DEVOLUCIONES UPDATE] Error:', err);
        res.status(500).json({ message: 'Error al actualizar' });
    }
});
console.log('✅ Ruta PUT /api/admin/devoluciones/:id configurada');

// ===================== ADMIN - RESEÑAS =====================
app.get('/api/admin/resenas', verificarAdmin, async (req, res) => {
    console.log('👑 [ADMIN RESEÑAS] Ruta llamada');
    try {
        const { rows: resenas } = await db.query(
            `SELECT r.*, u.nombre as usuario_nombre, p.nombre as producto_nombre
             FROM reseñas r
             JOIN usuarios u ON r.usuario_id = u.id
             JOIN productos p ON r.producto_id = p.id
             ORDER BY r.fecha DESC`
        );
        console.log(`✅ [ADMIN RESEÑAS] Reseñas encontradas: ${resenas.length}`);
        res.json(resenas);
    } catch (err) {
        console.error('❌ [ADMIN RESEÑAS] Error:', err);
        res.status(500).json({ message: 'Error al obtener reseñas' });
    }
});
console.log('✅ Ruta GET /api/admin/resenas configurada');

app.put('/api/admin/resenas/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN RESEÑAS UPDATE] Ruta llamada para reseña: ${id}`);
    
    const { estado } = req.body;

    const estadosValidos = ['pendiente', 'aprobada', 'rechazada'];
    if (!estadosValidos.includes(estado)) {
        console.log('❌ [ADMIN RESEÑAS UPDATE] Estado no válido:', estado);
        return res.status(400).json({ message: 'Estado no válido' });
    }

    try {
        await db.query('UPDATE reseñas SET estado = $1 WHERE id = $2', [estado, id]);
        console.log('✅ [ADMIN RESEÑAS UPDATE] Estado actualizado');
        res.json({ message: 'Estado actualizado' });
    } catch (err) {
        console.error('❌ [ADMIN RESEÑAS UPDATE] Error:', err);
        res.status(500).json({ message: 'Error al actualizar' });
    }
});
console.log('✅ Ruta PUT /api/admin/resenas/:id configurada');

app.delete('/api/admin/resenas/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`👑 [ADMIN RESEÑAS DELETE] Ruta llamada para reseña: ${id}`);

    try {
        await db.query('DELETE FROM reseñas_votos WHERE reseña_id = $1', [id]);
        await db.query('DELETE FROM reseñas WHERE id = $1', [id]);
        console.log('✅ [ADMIN RESEÑAS DELETE] Reseña eliminada');
        res.json({ message: 'Reseña eliminada' });
    } catch (err) {
        console.error('❌ [ADMIN RESEÑAS DELETE] Error:', err);
        res.status(500).json({ message: 'Error al eliminar' });
    }
});
console.log('✅ Ruta DELETE /api/admin/resenas/:id configurada');

// ===================== ADMIN - DETALLE DE PEDIDO =====================
app.get('/api/admin/orders/:orderId', verificarAdmin, async (req, res) => {
    const { orderId } = req.params;
    console.log(`👑 [ADMIN ORDER DETAIL] Ruta llamada para pedido: ${orderId}`);

    try {
        const { rows: pedidos } = await db.query(
            `SELECT p.*, u.nombre as cliente_nombre, u.email as cliente_email
             FROM pedidos p
             JOIN usuarios u ON p.usuario_id = u.id
             WHERE p.id = $1`,
            [orderId]
        );

        if (pedidos.length === 0) {
            console.log('❌ [ADMIN ORDER DETAIL] Pedido no encontrado');
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        console.log('✅ [ADMIN ORDER DETAIL] Pedido encontrado');
        res.json(pedidos[0]);
    } catch (err) {
        console.error('❌ [ADMIN ORDER DETAIL] Error:', err);
        res.status(500).json({ message: 'Error al obtener pedido' });
    }
});
console.log('✅ Ruta GET /api/admin/orders/:orderId configurada');

app.get('/api/admin/orders/:orderId/items', verificarAdmin, async (req, res) => {
    const { orderId } = req.params;
    console.log(`👑 [ADMIN ORDER ITEMS] Ruta llamada para pedido: ${orderId}`);

    try {
        const { rows: items } = await db.query(
            `SELECT oi.*, p.nombre, p.imagen
             FROM order_items oi
             JOIN productos p ON oi.producto_id = p.id
             WHERE oi.pedido_id = $1`,
            [orderId]
        );

        console.log(`✅ [ADMIN ORDER ITEMS] Items encontrados: ${items.length}`);
        res.json(items);
    } catch (err) {
        console.error('❌ [ADMIN ORDER ITEMS] Error:', err);
        res.status(500).json({ message: 'Error al obtener items' });
    }
});
console.log('✅ Ruta GET /api/admin/orders/:orderId/items configurada');

// ===== RUTA DE EMERGENCIA PARA VACIAR CARRITO MANUALMENTE =====
app.post('/api/emergency-clear-cart', async (req, res) => {
    console.log('🚨 EMERGENCY CLEAR CART CALLED');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        
        console.log(`🚨 Buscando carrito para usuario ${usuarioId}`);
        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            return res.json({ message: 'No hay carrito', vaciado: false });
        }

        const carritoId = carrito[0].id;
        console.log(`🚨 Eliminando items del carrito ${carritoId}`);
        
        const deleteResult = await db.query('DELETE FROM cart_items WHERE carrito_id = $1', [carritoId]);
        
        console.log(`🚨 Eliminadas ${deleteResult.rowCount} filas`);
        res.json({ 
            message: 'Carrito vaciado manualmente', 
            vaciado: true,
            filas: deleteResult.rowCount 
        });

    } catch (err) {
        console.error('🚨 Error:', err);
        res.status(500).json({ message: 'Error' });
    }
});

// ===================== INICIAR SERVIDOR =====================
console.log('🚀 Iniciando servidor...');
app.listen(PORT, () =>
    console.log(`✅ Servidor corriendo en http://localhost:${PORT}`)
);