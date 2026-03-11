import express from 'express';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Garante pasta de uploads
const uploadDir = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',')
    : '*'
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static(uploadDir));

// Configuração do MySQL
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || 'localhost',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'pod_store',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Configuração do Multer
const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: Number(process.env.MAX_FILE_SIZE || 10 * 1024 * 1024)
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    }

    cb(new Error('Apenas imagens são permitidas'));
  }
});

// Middleware de autenticação
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
};

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    await conn.query('SELECT 1');
    conn.release();

    res.json({
      success: true,
      message: 'API funcionando'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========== AUTH ==========
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const conn = await pool.getConnection();
    const [users] = await conn.query(
      'SELECT * FROM users WHERE email = ? AND is_active = true',
      [email]
    );
    conn.release();

    if (users.length === 0) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Senha inválida' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [users] = await conn.query(
      'SELECT id, email, full_name, role FROM users WHERE id = ?',
      [req.user.id]
    );
    conn.release();

    if (users.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json(users[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== PRODUCTS ==========
app.get('/api/products', async (req, res) => {
  try {
    const { category, featured } = req.query;

    let query = 'SELECT * FROM products WHERE is_active = true';
    const params = [];

    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }

    if (featured === 'true') {
      query += ' AND is_featured = true';
    }

    query += ' ORDER BY created_at DESC';

    const conn = await pool.getConnection();
    const [products] = await conn.query(query, params);
    conn.release();

    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const conn = await pool.getConnection();

    const [products] = await conn.query(
      'SELECT * FROM products WHERE id = ?',
      [req.params.id]
    );

    const [flavors] = await conn.query(
      `SELECT f.*
       FROM flavors f
       JOIN product_flavors pf ON f.id = pf.flavor_id
       WHERE pf.product_id = ?`,
      [req.params.id]
    );

    conn.release();

    if (products.length === 0) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }

    res.json({
      ...products[0],
      flavors
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/products', verifyToken, async (req, res) => {
  let conn;

  try {
    const {
      name,
      description,
      price,
      image_url,
      category,
      stock,
      is_active = true,
      is_featured = false,
      low_stock_threshold = 5,
      flavor_ids = []
    } = req.body;

    conn = await pool.getConnection();

    const [result] = await conn.query(
      `INSERT INTO products
      (name, description, price, image_url, category, stock, is_active, is_featured, low_stock_threshold)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        description,
        price,
        image_url,
        category,
        stock ?? 0,
        is_active,
        is_featured,
        low_stock_threshold
      ]
    );

    if (Array.isArray(flavor_ids) && flavor_ids.length > 0) {
      for (const flavorId of flavor_ids) {
        await conn.query(
          'INSERT INTO product_flavors (product_id, flavor_id) VALUES (?, ?)',
          [result.insertId, flavorId]
        );
      }
    }

    res.json({
      id: result.insertId,
      name,
      description,
      price
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/products/:id', verifyToken, async (req, res) => {
  let conn;

  try {
    const {
      name,
      description,
      price,
      image_url,
      category,
      stock,
      is_active,
      is_featured,
      low_stock_threshold,
      flavor_ids
    } = req.body;

    conn = await pool.getConnection();

    await conn.query(
      `UPDATE products
       SET name = ?, description = ?, price = ?, image_url = ?, category = ?, stock = ?,
           is_active = ?, is_featured = ?, low_stock_threshold = ?
       WHERE id = ?`,
      [
        name,
        description,
        price,
        image_url,
        category,
        stock,
        is_active,
        is_featured,
        low_stock_threshold,
        req.params.id
      ]
    );

    if (Array.isArray(flavor_ids)) {
      await conn.query(
        'DELETE FROM product_flavors WHERE product_id = ?',
        [req.params.id]
      );

      for (const flavorId of flavor_ids) {
        await conn.query(
          'INSERT INTO product_flavors (product_id, flavor_id) VALUES (?, ?)',
          [req.params.id, flavorId]
        );
      }
    }

    res.json({
      id: req.params.id,
      success: true
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (conn) conn.release();
  }
});

app.delete('/api/products/:id', verifyToken, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    await conn.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    conn.release();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== FLAVORS ==========
app.get('/api/flavors', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [flavors] = await conn.query(
      'SELECT * FROM flavors WHERE is_active = true ORDER BY name ASC'
    );
    conn.release();

    res.json(flavors);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/flavors', verifyToken, async (req, res) => {
  try {
    const { name } = req.body;

    const conn = await pool.getConnection();
    const [result] = await conn.query(
      'INSERT INTO flavors (name) VALUES (?)',
      [name]
    );
    conn.release();

    res.json({
      id: result.insertId,
      name
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/flavors/:id', verifyToken, async (req, res) => {
  try {
    const { name, is_active } = req.body;

    const conn = await pool.getConnection();
    await conn.query(
      'UPDATE flavors SET name = ?, is_active = ? WHERE id = ?',
      [name, is_active, req.params.id]
    );
    conn.release();

    res.json({
      id: req.params.id,
      name,
      is_active
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/flavors/:id', verifyToken, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    await conn.query('DELETE FROM flavors WHERE id = ?', [req.params.id]);
    conn.release();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== BANNERS ==========
app.get('/api/banners', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [banners] = await conn.query(
      'SELECT * FROM banners WHERE is_active = true ORDER BY `order` ASC, id DESC'
    );
    conn.release();

    res.json(banners);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/banners', verifyToken, async (req, res) => {
  try {
    const { title, subtitle, image_url, is_active = true, order = 0 } = req.body;

    const conn = await pool.getConnection();
    const [result] = await conn.query(
      'INSERT INTO banners (title, subtitle, image_url, is_active, `order`) VALUES (?, ?, ?, ?, ?)',
      [title, subtitle, image_url, is_active, order]
    );
    conn.release();

    res.json({
      id: result.insertId,
      title,
      subtitle,
      image_url,
      is_active,
      order
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/banners/:id', verifyToken, async (req, res) => {
  try {
    const { title, subtitle, image_url, is_active, order } = req.body;

    const conn = await pool.getConnection();
    await conn.query(
      'UPDATE banners SET title = ?, subtitle = ?, image_url = ?, is_active = ?, `order` = ? WHERE id = ?',
      [title, subtitle, image_url, is_active, order, req.params.id]
    );
    conn.release();

    res.json({
      id: req.params.id,
      title,
      subtitle,
      image_url,
      is_active,
      order
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/banners/:id', verifyToken, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    await conn.query('DELETE FROM banners WHERE id = ?', [req.params.id]);
    conn.release();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ORDERS ==========
app.get('/api/orders', verifyToken, async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();
    const [orders] = await conn.query(
      'SELECT * FROM orders ORDER BY created_at DESC'
    );

    for (const order of orders) {
      const [items] = await conn.query(
        'SELECT * FROM order_items WHERE order_id = ?',
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/orders/:id', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [orders] = await conn.query(
      'SELECT * FROM orders WHERE id = ?',
      [req.params.id]
    );

    const [items] = await conn.query(
      'SELECT * FROM order_items WHERE order_id = ?',
      [req.params.id]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Pedido não encontrado' });
    }

    res.json({
      ...orders[0],
      items
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/orders', async (req, res) => {
  let conn;

  try {
    const {
      customer_name,
      customer_phone,
      address = {},
      items = [],
      subtotal = 0,
      delivery_fee = 0,
      total = 0
    } = req.body;

    conn = await pool.getConnection();

    const [result] = await conn.query(
      `INSERT INTO orders
      (
        customer_name,
        customer_phone,
        address_cep,
        address_street,
        address_number,
        address_complement,
        address_neighborhood,
        address_city,
        address_state,
        address_reference,
        subtotal,
        delivery_fee,
        total
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        customer_name,
        customer_phone,
        address.cep || null,
        address.street || null,
        address.number || null,
        address.complement || null,
        address.neighborhood || null,
        address.city || null,
        address.state || null,
        address.reference || null,
        subtotal,
        delivery_fee,
        total
      ]
    );

    for (const item of items) {
      await conn.query(
        `INSERT INTO order_items
        (order_id, product_id, product_name, flavor, quantity, unit_price, subtotal)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          result.insertId,
          item.product_id || null,
          item.product_name,
          item.flavor || null,
          item.quantity,
          item.unit_price,
          item.subtotal
        ]
      );
    }

    res.json({
      id: result.insertId,
      customer_name,
      customer_phone,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/orders/:id', verifyToken, async (req, res) => {
  try {
    const { status } = req.body;

    const conn = await pool.getConnection();
    await conn.query(
      'UPDATE orders SET status = ? WHERE id = ?',
      [status, req.params.id]
    );
    conn.release();

    res.json({
      id: req.params.id,
      status
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== SETTINGS ==========
app.get('/api/settings', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [settings] = await conn.query(
      'SELECT * FROM site_settings LIMIT 1'
    );
    conn.release();

    res.json(settings[0] || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/settings', verifyToken, async (req, res) => {
  try {
    const conn = await pool.getConnection();

    const [rows] = await conn.query('SELECT id FROM site_settings LIMIT 1');

    if (rows.length === 0) {
      await conn.query('INSERT INTO site_settings () VALUES ()');
    }

    const updates = Object.keys(req.body)
      .map((key) => `\`${key}\` = ?`)
      .join(', ');

    const values = Object.values(req.body);

    if (!updates) {
      conn.release();
      return res.json({});
    }

    await conn.query(
      `UPDATE site_settings SET ${updates} WHERE id = 1`,
      values
    );

    conn.release();
    res.json(req.body);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== UPLOAD ==========
app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  }

  const baseUrl = process.env.API_URL || 'http://localhost:3001';
  const fileUrl = `${baseUrl}/uploads/${req.file.filename}`;

  res.json({
    file_url: fileUrl
  });
});

// ========== SPIN WHEEL CONFIG ==========
app.get('/api/spin-wheel-config', async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [config] = await conn.query(
      'SELECT * FROM spin_wheel_config WHERE is_active = true ORDER BY id ASC'
    );
    conn.release();

    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/spin-wheel-config', verifyToken, async (req, res) => {
  try {
    const {
      prize_label,
      prize_type,
      prize_value,
      prize_color,
      prize_image_url,
      prize_weight = 1,
      is_active = true
    } = req.body;

    const conn = await pool.getConnection();
    const [result] = await conn.query(
      `INSERT INTO spin_wheel_config
      (prize_label, prize_type, prize_value, prize_color, prize_image_url, prize_weight, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        prize_label,
        prize_type,
        prize_value,
        prize_color,
        prize_image_url,
        prize_weight,
        is_active
      ]
    );

    conn.release();

    res.json({
      id: result.insertId,
      prize_label,
      prize_type,
      prize_value
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tratamento de erro do multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }

  if (err) {
    return res.status(400).json({ error: err.message });
  }

  next();
});

// Inicializa servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});