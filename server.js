const express = require('express');
const cors = require('cors');
const db = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
require('dotenv').config();
const validateEmail = require('./services/emailValidation');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
// Manejador global de errores no capturados
process.on('uncaughtException', (err) => {
    console.error('❌ ERROR NO CAPTURADO:', err);
    console.error('Stack:', err.stack);
    // No salimos del proceso para poder ver el error
});

process.on('unhandledRejection', (err) => {
    console.error('❌ PROMESA RECHAZADA NO MANEJADA:', err);
});

// Verificar JWT_SECRET
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET no está definido en .env');
    process.exit(1);
}
// Verificar variables de entorno críticas
const requiredEnv = ['JWT_SECRET', 'DATABASE_URL', 'STRIPE_SECRET_KEY'];
requiredEnv.forEach(envVar => {
    if (!process.env[envVar]) {
        console.error(`❌ Variable de entorno ${envVar} no definida`);
        process.exit(1);
    }
});
// ===== CONFIGURACIÓN DE SEGURIDAD =====

// 1. Helmet - Protección de cabeceras HTTP
app.use(helmet());

// 2. Deshabilitar x-powered-by (oculta que usas Express)
app.disable('x-powered-by');

// 3. Configuración de CORS
const corsOptions = {
    origin: process.env.NODE_ENV === 'production'
        ? ['https://tudominio.com']
        : ['http://localhost:5500', 'http://127.0.0.1:5500'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

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

app.use('/api/', limiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// ===== WEBHOOK DE STRIPE =====
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('✅ Webhook verificado. Tipo:', event.type);
    } catch (err) {
        console.log(`❌ Error de firma del webhook: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        
        const usuarioId = session.metadata.usuarioId;
        const carritoId = session.metadata.carritoId;
        const total = parseFloat(session.metadata.total);
        const descuento = parseFloat(session.metadata.descuento);
        const cuponId = session.metadata.cuponId || null;
        
        console.log(`✅ Pago completado para usuario ${usuarioId}`);

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

            const { rows: pedidoRows } = await db.query(
                `INSERT INTO pedidos 
                 (usuario_id, total, estado, fecha, direccion_envio, direccion_detalles, cupon_id, descuento_aplicado, stripe_session_id) 
                 VALUES ($1, $2, 'pagado', NOW(), $3, $4, $5, $6, $7) RETURNING id`,
                [usuarioId, total, direccionEnvio, direccionDetalles, cuponId, descuento, session.id]
            );
            
            const pedidoId = pedidoRows[0].id;
            console.log(`🎉 Pedido creado ID: ${pedidoId}`);

            const { rows: items } = await db.query(
                `SELECT ci.cantidad, ci.precio_unitario, p.id as producto_id
                 FROM cart_items ci
                 JOIN productos p ON ci.producto_id = p.id
                 WHERE ci.carrito_id = $1`,
                [carritoId]
            );

            for (const item of items) {
                await db.query(
                    'INSERT INTO order_items (pedido_id, producto_id, cantidad, precio) VALUES ($1, $2, $3, $4)',
                    [pedidoId, item.producto_id, item.cantidad, parseFloat(item.precio_unitario)]
                );
            }

            await db.query('DELETE FROM cart_items WHERE carrito_id = $1', [carritoId]);

            if (cuponId) {
                await db.query(
                    'UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE id = $1',
                    [cuponId]
                );
            }

            console.log(`✅ Pedido ${pedidoId} completado con dirección: ${direccionEnvio || 'No especificada'}`);

        } catch (err) {
            console.error('❌ Error en webhook:', err);
        }
    }

    res.json({received: true});
});
app.use(express.json());

// ===================== REGISTRO CON VALIDACIÓN =====================
app.post('/api/register',
    [
        body('nombre').notEmpty().withMessage('El nombre es obligatorio').trim().escape(),
        body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
        body('contraseña').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                message: 'Error de validación', 
                errors: errors.array() 
            });
        }

        const { nombre, email, contraseña } = req.body;

        try {
            console.log(`🔍 Validando email: ${email}`);
            const validation = await validateEmail(email);
            
            if (!validation.isValid) {
                console.log('❌ Email no válido:', validation.message);
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

            const { rows: existing } = await db.query(
                'SELECT * FROM usuarios WHERE email = $1',
                [email]
            );

            if (existing.length > 0) {
                return res.status(400).json({ message: 'El usuario ya existe' });
            }

            const hashedPassword = await bcrypt.hash(contraseña, 10);
            const { rows: newUser } = await db.query(
                'INSERT INTO usuarios (nombre, email, contraseña) VALUES ($1, $2, $3) RETURNING id',
                [nombre, email, hashedPassword]
            );

            const token = jwt.sign({ userId: newUser[0].id }, JWT_SECRET, { expiresIn: '30d' });

            res.json({
                message: 'Usuario registrado',
                token,
                userId: newUser[0].id,
                nombre
            });

        } catch (err) {
            console.error('Error en registro:', err);
            res.status(500).json({ message: err.message });
        }
    }
);

// ===================== VERIFICAR ADMIN =====================
app.get('/api/user/is-admin', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.json({ isAdmin: false });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { rows } = await db.query(
            'SELECT is_admin FROM usuarios WHERE id = $1',
            [decoded.userId]
        );

        if (rows.length > 0 && rows[0].is_admin) {
            res.json({ isAdmin: true });
        } else {
            res.json({ isAdmin: false });
        }

    } catch (err) {
        console.error('Error verificando admin:', err);
        res.json({ isAdmin: false });
    }
});

// ===================== LOGIN CON VALIDACIÓN =====================
app.post('/api/login',
    [
        body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
        body('contraseña').notEmpty().withMessage('La contraseña es obligatoria')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, contraseña } = req.body;

        try {
            const { rows } = await db.query(
                'SELECT * FROM usuarios WHERE email = $1',
                [email]
            );

            if (rows.length === 0) {
                return res.status(401).json({ message: 'Credenciales incorrectas' });
            }

            const user = rows[0];
            const valid = await bcrypt.compare(contraseña, user.contraseña);

            if (!valid) {
                return res.status(401).json({ message: 'Credenciales incorrectas' });
            }

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

            res.json({
                message: 'Login exitoso',
                token,
                userId: user.id,
                nombre: user.nombre
            });

        } catch (err) {
            console.error('Error en login:', err);
            res.status(500).json({ message: err.message });
        }
    }
);

// ===================== PERFIL DE USUARIO =====================
app.get('/api/users/me', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { rows } = await db.query(
            'SELECT id, nombre, email, fecha_creacion FROM usuarios WHERE id = $1',
            [decoded.userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        res.json(rows[0]);

    } catch (err) {
        console.error('Error en perfil:', err);
        res.status(401).json({ message: 'Token inválido o expirado' });
    }
});

// ===================== ACTUALIZAR PERFIL =====================
app.put('/api/users/me', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { nombre } = req.body;
        
        await db.query(
            'UPDATE usuarios SET nombre = $1 WHERE id = $2',
            [nombre, decoded.userId]
        );

        res.json({ message: 'Perfil actualizado correctamente' });

    } catch (err) {
        console.error('Error actualizando perfil:', err);
        res.status(500).json({ message: err.message });
    }
});

// ===================== CAMBIAR CONTRASEÑA =====================
app.post('/api/users/change-password', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { currentPassword, newPassword } = req.body;

        const { rows } = await db.query(
            'SELECT contraseña FROM usuarios WHERE id = $1',
            [decoded.userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const valid = await bcrypt.compare(currentPassword, rows[0].contraseña);
        
        if (!valid) {
            return res.status(401).json({ message: 'Contraseña actual incorrecta' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query(
            'UPDATE usuarios SET contraseña = $1 WHERE id = $2',
            [hashedPassword, decoded.userId]
        );

        res.json({ message: 'Contraseña actualizada correctamente' });

    } catch (err) {
        console.error('Error cambiando contraseña:', err);
        res.status(500).json({ message: err.message });
    }
});

// ===================== CONTACTO CON VALIDACIÓN =====================
app.post('/api/contact',
    [
        body('name').notEmpty().withMessage('El nombre es obligatorio').trim().escape(),
        body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
        body('subject').optional().trim().escape(),
        body('message').notEmpty().withMessage('El mensaje es obligatorio').trim().escape()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, subject, message } = req.body;

        try {
            await db.query(
                'INSERT INTO contact_messages (nombre, email, asunto, mensaje) VALUES ($1, $2, $3, $4)',
                [name, email, subject || 'Sin asunto', message]
            );
            console.log('✅ Mensaje guardado en BD');

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            await transporter.verify();

            const mailOptions = {
                from: `"Formulario Web" <${process.env.EMAIL_USER}>`,
                to: 'guilleriveraa12@gmail.com',
                replyTo: email,
                subject: `📬 ${subject || 'Nuevo mensaje'} de ${name}`,
                html: `...` // Mantén tu HTML aquí
            };

            await transporter.sendMail(mailOptions);
            res.json({ message: "Mensaje enviado correctamente" });

        } catch (err) {
            console.error('❌ Error en contacto:', err);
            res.status(500).json({ message: "Error al enviar el mensaje" });
        }
    }
);

// ===================== CARRITO =====================
async function getOrCreateCart(usuarioId) {
    const { rows: carrito } = await db.query(
        'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
        [usuarioId]
    );
    
    if (carrito.length === 0) {
        const { rows: newCart } = await db.query(
            'INSERT INTO carritos (usuario_id) VALUES ($1) RETURNING id',
            [usuarioId]
        );
        return newCart[0].id;
    }
    
    return carrito[0].id;
}

// Obtener carrito
app.get('/api/cart', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            return res.json({ items: [], subtotal: 0, shipping: 0, total: 0 });
        }

        const carritoId = carrito[0].id;
        const { rows: items } = await db.query(
            `SELECT ci.cantidad, ci.precio_unitario, p.id as producto_id, p.nombre, p.imagen
             FROM cart_items ci
             JOIN productos p ON ci.producto_id = p.id
             WHERE ci.carrito_id = $1`,
            [carritoId]
        );

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

        res.json({
            items: formattedItems,
            subtotal,
            shipping,
            total
        });

    } catch (err) {
        console.error('Error obteniendo carrito:', err);
        res.status(500).json({ message: 'Error al obtener el carrito' });
    }
});

// Añadir producto al carrito
app.post('/api/cart/add', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { productId, quantity = 1 } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: product } = await db.query(
            'SELECT * FROM productos WHERE id = $1',
            [productId]
        );

        if (product.length === 0) {
            return res.status(404).json({ message: 'Producto no encontrado' });
        }

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
        } else {
            carritoId = carrito[0].id;
        }

        const { rows: existing } = await db.query(
            'SELECT id, cantidad FROM cart_items WHERE carrito_id = $1 AND producto_id = $2',
            [carritoId, productId]
        );

        if (existing.length > 0) {
            await db.query(
                'UPDATE cart_items SET cantidad = cantidad + $1 WHERE id = $2',
                [quantity, existing[0].id]
            );
        } else {
            await db.query(
                'INSERT INTO cart_items (carrito_id, producto_id, cantidad, precio_unitario) VALUES ($1, $2, $3, $4)',
                [carritoId, productId, quantity, product[0].precio]
            );
        }

        res.json({ message: 'Producto añadido al carrito' });

    } catch (err) {
        console.error('Error añadiendo producto:', err);
        res.status(500).json({ message: 'Error al añadir producto' });
    }
});

// Actualizar cantidad
app.post('/api/cart/update', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { productId, delta } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            return res.status(404).json({ message: 'Carrito no encontrado' });
        }

        const carritoId = carrito[0].id;

        if (delta > 0) {
            await db.query(
                'UPDATE cart_items SET cantidad = cantidad + $1 WHERE carrito_id = $2 AND producto_id = $3',
                [delta, carritoId, productId]
            );
        } else {
            await db.query(
                'UPDATE cart_items SET cantidad = cantidad + $1 WHERE carrito_id = $2 AND producto_id = $3 AND cantidad > $4',
                [delta, carritoId, productId, -delta]
            );
            
            await db.query(
                'DELETE FROM cart_items WHERE carrito_id = $1 AND producto_id = $2 AND cantidad <= 0',
                [carritoId, productId]
            );
        }

        res.json({ message: 'Carrito actualizado' });

    } catch (err) {
        console.error('Error actualizando carrito:', err);
        res.status(500).json({ message: 'Error al actualizar carrito' });
    }
});

// Eliminar producto del carrito
app.delete('/api/cart/remove/:productId', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { productId } = req.params;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: carrito } = await db.query(
            'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
            [usuarioId]
        );

        if (carrito.length === 0) {
            return res.status(404).json({ message: 'Carrito no encontrado' });
        }

        await db.query(
            'DELETE FROM cart_items WHERE carrito_id = $1 AND producto_id = $2',
            [carrito[0].id, productId]
        );

        res.json({ message: 'Producto eliminado del carrito' });

    } catch (err) {
        console.error('Error eliminando producto:', err);
        res.status(500).json({ message: 'Error al eliminar producto' });
    }
});

// ===================== PRODUCTOS =====================
app.get('/api/productos', async (req, res) => {
    const { categoria } = req.query;
    
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
        res.json(productos);
        
    } catch (err) {
        console.error('❌ Error:', err);
        res.status(500).json({ message: 'Error al obtener productos' });
    }
});

app.get('/api/productos/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const { rows: productos } = await db.query(
            `SELECT p.*, c.nombre as categoria_nombre
             FROM productos p
             LEFT JOIN categorias c ON p.categoria_id = c.id
             WHERE p.id = $1`,
            [id]
        );
        
        if (productos.length === 0) {
            return res.status(404).json({ message: 'Producto no encontrado' });
        }
        
        res.json(productos[0]);
        
    } catch (err) {
        console.error('❌ Error:', err);
        res.status(500).json({ message: 'Error al obtener producto' });
    }
});

app.get('/api/categorias', async (req, res) => {
    try {
        const { rows: categorias } = await db.query(
            'SELECT * FROM categorias ORDER BY nombre ASC'
        );
        res.json(categorias);
    } catch (err) {
        console.error('❌ Error:', err);
        res.status(500).json({ message: 'Error al obtener categorías' });
    }
});

// ===================== CUPONES DE DESCUENTO =====================
app.post('/api/cupones/validar', async (req, res) => {
    const { codigo, subtotal, usuarioId } = req.body;
    
    if (!codigo) {
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
            return res.json({ valido: false, message: 'Cupón no válido o expirado' });
        }

        const cupon = cupones[0];

        if (subtotal && cupon.monto_minimo > subtotal) {
            return res.json({ 
                valido: false, 
                message: `Monto mínimo de ${parseFloat(cupon.monto_minimo).toFixed(2)}€` 
            });
        }

        if (cupon.usos_actuales >= cupon.uso_maximo) {
            return res.json({ valido: false, message: 'Cupón agotado' });
        }

        if (usuarioId) {
            const { rows: usado } = await db.query(
                'SELECT * FROM cupones_usados WHERE cupon_id = $1 AND usuario_id = $2',
                [cupon.id, usuarioId]
            );

            if (usado.length >= cupon.uso_por_usuario) {
                return res.json({ valido: false, message: 'Ya has usado este cupón' });
            }
        }

        let descuento = 0;
        if (cupon.tipo_descuento === 'porcentaje') {
            descuento = (parseFloat(subtotal) * parseFloat(cupon.valor_descuento) / 100);
        } else {
            descuento = parseFloat(cupon.valor_descuento);
        }

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
        console.error('❌ Error validando cupón:', err);
        res.status(500).json({ message: 'Error al validar cupón' });
    }
});

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
        console.log('💳 Creando sesión de pago');
        
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'No autorizado' });
        }

        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            const usuarioId = decoded.userId;

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
                console.log('📍 Dirección:', direccionEnvio);
            }

            const { rows: carrito } = await db.query(
                'SELECT id FROM carritos WHERE usuario_id = $1 ORDER BY fecha_creacion DESC LIMIT 1',
                [usuarioId]
            );

            if (carrito.length === 0) {
                return res.status(404).json({ message: 'Carrito vacío' });
            }

            const carritoId = carrito[0].id;

            const { rows: items } = await db.query(
                `SELECT ci.cantidad, ci.precio_unitario, p.id as producto_id, p.nombre
                 FROM cart_items ci
                 JOIN productos p ON ci.producto_id = p.id
                 WHERE ci.carrito_id = $1`,
                [carritoId]
            );

            if (items.length === 0) {
                return res.status(404).json({ message: 'Carrito vacío' });
            }

            let subtotal = 0;
            items.forEach(item => {
                const precio = parseFloat(item.precio_unitario) || 0;
                const cantidad = parseInt(item.cantidad) || 0;
                subtotal += precio * cantidad;
            });

            const shipping = subtotal > 50 ? 0 : 4.99;

            let descuento = 0;
            let cuponId = null;

            if (req.body.cuponId) {
                const { rows: cupones } = await db.query(
                    'SELECT * FROM cupones WHERE id = $1 AND activo = TRUE AND (fecha_fin IS NULL OR fecha_fin >= NOW())',
                    [req.body.cuponId]
                );
                
                if (cupones.length > 0) {
                    const cupon = cupones[0];
                    
                    if (!cupon.monto_minimo || subtotal >= cupon.monto_minimo) {
                        if (cupon.tipo_descuento === 'porcentaje') {
                            descuento = (subtotal * cupon.valor_descuento) / 100;
                        } else {
                            descuento = cupon.valor_descuento;
                        }
                        cuponId = cupon.id;
                        
                        if (descuento > subtotal) {
                            descuento = subtotal;
                        }
                    }
                }
            }

            const totalFinal = Math.max(0, subtotal - descuento + shipping);

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

            let sessionParams = {
                payment_method_types: ['card'],
                line_items: lineItems,
                mode: 'payment',
                success_url: `${process.env.BASE_URL}/fronted/pedido-exitoso.html?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.BASE_URL}/fronted/carrito.html?cancelado=true`,
                shipping_address_collection: { allowed_countries: ['ES'] },
                metadata: {
                    usuarioId: String(usuarioId),
                    carritoId: String(carritoId),
                    subtotal: String(subtotal.toFixed(2)),
                    descuento: String(descuento.toFixed(2)),
                    shipping: String(shipping.toFixed(2)),
                    total: String(totalFinal.toFixed(2)),
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
            console.log('✅ Sesión de Stripe creada:', session.id);
            
            res.json({ id: session.id, url: session.url });

        } catch (err) {
            console.error('❌ Error creando sesión de pago:', err);
            const errorMessage = process.env.NODE_ENV === 'production' 
                ? 'Error al procesar el pago' 
                : err.message;
            res.status(500).json({ message: errorMessage });
        }
    }
);

// ===================== PEDIDOS =====================

// 🔴 PRIMERO: RUTA ESPECÍFICA DE DEVOLUCIONES
app.get('/api/orders/eligible-for-return', async (req, res) => {
    console.log('\n========== DEVOLUCIONES ==========');
    console.log('📦 Ruta de devoluciones llamada');
    
    const authHeader = req.headers.authorization;
    console.log('Auth header existe:', !!authHeader);
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ No autorizado - header inválido');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    console.log('Token recibido (primeros 20 chars):', token.substring(0, 20) + '...');

    try {
        console.log('🔐 Verificando token...');
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ Token válido. Usuario ID:', usuarioId);

        console.log('📊 Consultando pedidos elegibles...');
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

        console.log(`📦 Pedidos encontrados: ${pedidos.length}`);
        
        if (pedidos.length === 0) {
            console.log('ℹ️ No hay pedidos elegibles');
            return res.json([]);
        }

        const pedidosConItems = await Promise.all(pedidos.map(async (pedido) => {
            console.log(`🔍 Buscando items para pedido ${pedido.id}...`);
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

        console.log('✅ Respuesta enviada correctamente');
        res.json(pedidosConItems);

    } catch (err) {
        console.error('❌ ERROR EN DEVOLUCIONES:');
        console.error('   Mensaje:', err.message);
        console.error('   Stack:', err.stack);
        res.status(500).json({ message: 'Error al obtener pedidos: ' + err.message });
    }
});

// 🟡 SEGUNDO: RUTA DE MIS PEDIDOS
app.get('/api/orders/my-orders', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

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

        res.json(pedidos);

    } catch (err) {
        console.error('❌ Error obteniendo pedidos:', err);
        res.status(500).json({ message: 'Error al obtener pedidos' });
    }
});

// 🟢 TERCERO: RUTAS CON PARÁMETROS
app.get('/api/orders/:orderId', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { orderId } = req.params;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: pedidos } = await db.query(
            'SELECT * FROM pedidos WHERE id = $1 AND usuario_id = $2',
            [orderId, usuarioId]
        );

        if (pedidos.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        res.json(pedidos[0]);

    } catch (err) {
        console.error('❌ Error obteniendo pedido:', err);
        res.status(500).json({ message: 'Error al obtener pedido' });
    }
});

app.get('/api/orders/:orderId/items', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { orderId } = req.params;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: pedido } = await db.query(
            'SELECT id FROM pedidos WHERE id = $1 AND usuario_id = $2',
            [orderId, usuarioId]
        );

        if (pedido.length === 0) {
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

        res.json(items);

    } catch (err) {
        console.error('❌ Error obteniendo items:', err);
        res.status(500).json({ message: 'Error al obtener items' });
    }
});

// ===================== DEVOLUCIONES =====================

// Ruta GET para obtener pedidos elegibles
app.get('/api/orders/eligible-for-return', async (req, res) => {
    console.log('\n========== DEVOLUCIONES GET ==========');
    console.log('📦 Ruta de devoluciones llamada');
    
    const authHeader = req.headers.authorization;
    console.log('Auth header existe:', !!authHeader);
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ No autorizado - header inválido');
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    console.log('Token recibido (primeros 20 chars):', token.substring(0, 20) + '...');

    try {
        console.log('🔐 Verificando token...');
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;
        console.log('✅ Token válido. Usuario ID:', usuarioId);

        console.log('📊 Consultando pedidos elegibles...');
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

        console.log(`📦 Pedidos encontrados: ${pedidos.length}`);
        
        if (pedidos.length === 0) {
            console.log('ℹ️ No hay pedidos elegibles');
            return res.json([]);
        }

        const pedidosConItems = await Promise.all(pedidos.map(async (pedido) => {
            console.log(`🔍 Buscando items para pedido ${pedido.id}...`);
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

        console.log('✅ Respuesta enviada correctamente');
        res.json(pedidosConItems);

    } catch (err) {
        console.error('❌ ERROR EN DEVOLUCIONES:');
        console.error('   Mensaje:', err.message);
        console.error('   Stack:', err.stack);
        res.status(500).json({ message: 'Error al obtener pedidos: ' + err.message });
    }
});

// Ruta POST para crear una devolución
app.post('/api/returns', async (req, res) => {
    console.log('\n========== CREAR DEVOLUCIÓN ==========');
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    const token = authHeader.split(' ')[1];
    const { orderId, reason } = req.body;
    
    console.log('📦 Solicitando devolución para pedido:', orderId);
    console.log('📝 Motivo:', reason);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const usuarioId = decoded.userId;

        const { rows: pedido } = await db.query(
            'SELECT * FROM pedidos WHERE id = $1 AND usuario_id = $2',
            [orderId, usuarioId]
        );

        if (pedido.length === 0) {
            console.log('❌ Pedido no encontrado o no pertenece al usuario');
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        await db.query(
            'INSERT INTO devoluciones (pedido_id, motivo, estado) VALUES ($1, $2, $3)',
            [orderId, reason, 'pendiente']
        );

        console.log('✅ Devolución solicitada para pedido:', orderId);
        res.json({ message: 'Solicitud de devolución enviada correctamente' });

    } catch (err) {
        console.error('❌ Error creando devolución:', err);
        res.status(500).json({ message: 'Error al procesar la devolución' });
    }
});


// ===================== ADMIN - RUTAS PARA EL PANEL =====================
async function verificarAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No autorizado' });
    }

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { rows } = await db.query('SELECT is_admin FROM usuarios WHERE id = $1', [decoded.userId]);
        
        if (!rows[0]?.is_admin) {
            return res.status(403).json({ message: 'Acceso denegado' });
        }
        
        req.usuarioId = decoded.userId;
        next();
    } catch (err) {
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
    try {
        const { rows: pedidos } = await db.query(
            `SELECT p.*, u.nombre as cliente_nombre, u.email as cliente_email
             FROM pedidos p
             JOIN usuarios u ON p.usuario_id = u.id
             ORDER BY p.fecha DESC`
        );
        res.json(pedidos);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener pedidos' });
    }
});

app.put('/api/admin/pedidos/:id', verificarAdmin, orderStatusValidator, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { estado } = req.body;

    try {
        const { rowCount } = await db.query(
            'UPDATE pedidos SET estado = $1 WHERE id = $2',
            [estado, id]
        );

        if (rowCount === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        res.json({ message: 'Estado actualizado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar' });
    }
});

app.get('/api/admin/ultimos-pedidos', verificarAdmin, async (req, res) => {
    const limite = req.query.limite ? parseInt(req.query.limite) : 5;
    if (isNaN(limite) || limite <= 0 || limite > 100) {
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
        res.json(pedidos);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener pedidos' });
    }
});

app.get('/api/admin/cupones', verificarAdmin, async (req, res) => {
    try {
        const { rows: cupones } = await db.query('SELECT * FROM cupones ORDER BY created_at DESC');
        res.json(cupones);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener cupones' });
    }
});

app.post('/api/admin/cupones', verificarAdmin, couponValidator, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { codigo, descripcion, tipo_descuento, valor_descuento, monto_minimo, fecha_fin, uso_maximo } = req.body;

    try {
        const { rows: newCupon } = await db.query(
            `INSERT INTO cupones 
             (codigo, descripcion, tipo_descuento, valor_descuento, monto_minimo, fecha_fin, uso_maximo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
            [codigo, descripcion, tipo_descuento, valor_descuento, monto_minimo || 0, fecha_fin || null, uso_maximo || 1]
        );

        res.json({ message: 'Cupón creado', id: newCupon[0].id });
    } catch (err) {
        res.status(500).json({ message: 'Error al crear cupón' });
    }
});

app.put('/api/admin/cupones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    const { activo } = req.body;

    if (typeof activo !== 'boolean') {
        return res.status(400).json({ message: 'activo debe ser booleano' });
    }

    try {
        await db.query('UPDATE cupones SET activo = $1 WHERE id = $2', [activo, id]);
        res.json({ message: 'Cupón actualizado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar' });
    }
});

app.delete('/api/admin/cupones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;

    if (isNaN(parseInt(id))) {
        return res.status(400).json({ message: 'ID inválido' });
    }

    try {
        await db.query('DELETE FROM cupones WHERE id = $1', [id]);
        res.json({ message: 'Cupón eliminado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al eliminar' });
    }
});

app.post('/api/admin/productos', verificarAdmin, productValidator, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { nombre, descripcion, precio, imagen, categoria_id } = req.body;

    try {
        const { rows: newProduct } = await db.query(
            'INSERT INTO productos (nombre, descripcion, precio, imagen, categoria_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [nombre, descripcion, precio, imagen, categoria_id]
        );
        res.json({ message: 'Producto creado', id: newProduct[0].id });
    } catch (err) {
        res.status(500).json({ message: 'Error al crear producto' });
    }
});

app.put('/api/admin/productos/:id', verificarAdmin, productValidator, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { nombre, descripcion, precio, imagen, categoria_id } = req.body;

    try {
        await db.query(
            'UPDATE productos SET nombre = $1, descripcion = $2, precio = $3, imagen = $4, categoria_id = $5 WHERE id = $6',
            [nombre, descripcion, precio, imagen, categoria_id, id]
        );
        res.json({ message: 'Producto actualizado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar producto' });
    }
});

app.delete('/api/admin/productos/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('DELETE FROM productos WHERE id = $1', [id]);
        res.json({ message: 'Producto eliminado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al eliminar producto' });
    }
});

// ===================== ADMIN - DEVOLUCIONES =====================
app.get('/api/admin/devoluciones', verificarAdmin, async (req, res) => {
    try {
        const { rows: devoluciones } = await db.query(
            `SELECT d.*, u.nombre as cliente_nombre, u.email as cliente_email, p.total as pedido_total
             FROM devoluciones d
             JOIN pedidos p ON d.pedido_id = p.id
             JOIN usuarios u ON p.usuario_id = u.id
             ORDER BY d.fecha DESC`
        );
        res.json(devoluciones);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener devoluciones' });
    }
});

app.put('/api/admin/devoluciones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    const estadosValidos = ['pendiente', 'aprobada', 'rechazada', 'completada'];
    if (!estadosValidos.includes(estado)) {
        return res.status(400).json({ message: 'Estado no válido' });
    }

    try {
        await db.query(
            'UPDATE devoluciones SET estado = $1 WHERE id = $2',
            [estado, id]
        );
        res.json({ message: 'Estado actualizado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar' });
    }
});

// ===================== ADMIN - RESEÑAS =====================
app.get('/api/admin/resenas', verificarAdmin, async (req, res) => {
    try {
        const { rows: resenas } = await db.query(
            `SELECT r.*, u.nombre as usuario_nombre, p.nombre as producto_nombre
             FROM reseñas r
             JOIN usuarios u ON r.usuario_id = u.id
             JOIN productos p ON r.producto_id = p.id
             ORDER BY r.fecha DESC`
        );
        res.json(resenas);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener reseñas' });
    }
});

app.put('/api/admin/resenas/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    const estadosValidos = ['pendiente', 'aprobada', 'rechazada'];
    if (!estadosValidos.includes(estado)) {
        return res.status(400).json({ message: 'Estado no válido' });
    }

    try {
        await db.query('UPDATE reseñas SET estado = $1 WHERE id = $2', [estado, id]);
        res.json({ message: 'Estado actualizado' });
    } catch (err) {
        res.status(500).json({ message: 'Error al actualizar' });
    }
});

app.delete('/api/admin/resenas/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('DELETE FROM reseñas_votos WHERE reseña_id = $1', [id]);
        await db.query('DELETE FROM reseñas WHERE id = $1', [id]);
        res.json({ message: 'Reseña eliminada' });
    } catch (err) {
        res.status(500).json({ message: 'Error al eliminar' });
    }
});

// ===================== ADMIN - DETALLE DE PEDIDO =====================
app.get('/api/admin/orders/:orderId', verificarAdmin, async (req, res) => {
    const { orderId } = req.params;

    try {
        const { rows: pedidos } = await db.query(
            `SELECT p.*, u.nombre as cliente_nombre, u.email as cliente_email
             FROM pedidos p
             JOIN usuarios u ON p.usuario_id = u.id
             WHERE p.id = $1`,
            [orderId]
        );

        if (pedidos.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        res.json(pedidos[0]);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener pedido' });
    }
});

app.get('/api/admin/orders/:orderId/items', verificarAdmin, async (req, res) => {
    const { orderId } = req.params;

    try {
        const { rows: items } = await db.query(
            `SELECT oi.*, p.nombre, p.imagen
             FROM order_items oi
             JOIN productos p ON oi.producto_id = p.id
             WHERE oi.pedido_id = $1`,
            [orderId]
        );

        res.json(items);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener items' });
    }
});

// ===================== INICIAR SERVIDOR =====================
app.listen(PORT, () =>
    console.log(`Servidor corriendo en http://localhost:${PORT}`)
);