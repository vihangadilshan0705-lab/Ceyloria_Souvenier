
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

const publicDir = path.join(__dirname, 'public');
const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(publicDir, 'uploads', 'products');
const profileUploadDir = path.join(publicDir, 'uploads', 'profiles');

for (const dir of [
  dataDir,
  uploadDir,
  profileUploadDir
]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

const db = new Database(
  path.join(dataDir, 'ceyloria.sqlite')
);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const ORDER_STATUSES = [
  'Pending',
  'Order Confirmed',
  'Preparing',
  'Dispatched',
  'On the Way',
  'Delivered'
];

// =====================================
// STAFF PERMISSIONS
// =====================================

const STAFF_PERMISSION_NAMES = {
  dashboard: 'Dashboard & Reports',
  products: 'Products & Categories',
  orders: 'Orders',
  customers: 'Customers',
  stock: 'Stock Management',
  invoices: 'Invoices'
};

const ALL_STAFF_PERMISSIONS = Object.keys(
  STAFF_PERMISSION_NAMES
);

// =====================================
// DATABASE TABLES
// =====================================

db.exec(`
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  address TEXT,
  password_hash TEXT NOT NULL,
  registration_email_sent INTEGER DEFAULT 0,
  welcome_email_sent INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customer_password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_customer_password_resets_customer
  ON customer_password_resets(customer_id);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT NOT NULL UNIQUE,
  invoice_token TEXT NOT NULL UNIQUE,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  address TEXT NOT NULL,
  payment TEXT,
  country TEXT,
  notes TEXT,
  items_json TEXT NOT NULL,
  subtotal REAL DEFAULT 0,
  status TEXT DEFAULT 'Pending',
  email_owner_sent INTEGER DEFAULT 0,
  email_customer_sent INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS product_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL COLLATE NOCASE,
  parent_id INTEGER DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(parent_id) REFERENCES product_categories(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price REAL NOT NULL DEFAULT 0,
  discount_price REAL DEFAULT NULL,
  material TEXT DEFAULT '',
  stock_quantity INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Active',
  category_id INTEGER,
  subcategory_id INTEGER DEFAULT NULL,
  size TEXT DEFAULT '',
  colours_json TEXT NOT NULL DEFAULT '[]',
  sizes_json TEXT NOT NULL DEFAULT '[]',
  images_json TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(category_id) REFERENCES product_categories(id)
    ON DELETE SET NULL,
  FOREIGN KEY(subcategory_id) REFERENCES product_categories(id)
    ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS chairman_account (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  full_name TEXT NOT NULL,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  email TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  profile_image TEXT DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS staff_positions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  email TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  position TEXT NOT NULL DEFAULT 'Staff',
  password_hash TEXT NOT NULL,
  profile_image TEXT DEFAULT '',
  permissions_json TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// =====================================
// SAFE DATABASE MIGRATION
// =====================================

function addColumnIfMissing(table, column, definition) {
  const columns = db.prepare(
    `PRAGMA table_info(${table})`
  ).all();

  if (!columns.some(col => col.name === column)) {
    db.exec(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    );
  }
}

addColumnIfMissing(
  'product_categories',
  'parent_id',
  'INTEGER DEFAULT NULL'
);

addColumnIfMissing(
  'products',
  'subcategory_id',
  'INTEGER DEFAULT NULL'
);

addColumnIfMissing(
  'products',
  'discount_price',
  'REAL DEFAULT NULL'
);

addColumnIfMissing(
  'products',
  'material',
  "TEXT DEFAULT ''"
);

addColumnIfMissing(
  'products',
  'stock_quantity',
  'INTEGER NOT NULL DEFAULT 100'
);

addColumnIfMissing(
  'products',
  'status',
  "TEXT NOT NULL DEFAULT 'Active'"
);

db.prepare(`
  UPDATE products
  SET status = CASE
    WHEN active = 0 THEN 'Inactive'
    ELSE 'Active'
  END
  WHERE status IS NULL OR status = ''
`).run();

db.prepare(`
  UPDATE products
  SET active = CASE
    WHEN LOWER(status) = 'inactive' THEN 0
    ELSE 1
  END
`).run();

// Remove old global UNIQUE(name) constraint safely.
const categoryIndexes = db.prepare(
  `PRAGMA index_list(product_categories)`
).all();

const hasOldUniqueName = categoryIndexes.some(index => {
  if (!index.unique || index.origin !== 'u') {    return false;
  }

  const columns = db.prepare(
    `PRAGMA index_info("${index.name}")`
  ).all();

  return columns.length === 1 &&
    columns[0].name === 'name';
});

if (hasOldUniqueName) {
  console.log(
    'Updating product category database structure...'
  );

  db.pragma('foreign_keys = OFF');

  try {
    const migrateCategories = db.transaction(() => {
      db.exec(`
        CREATE TABLE product_categories_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL COLLATE NOCASE,
          parent_id INTEGER DEFAULT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(parent_id)
            REFERENCES product_categories_new(id)
            ON DELETE CASCADE
        );

        INSERT INTO product_categories_new
          (id, name, parent_id, created_at)
        SELECT id, name, parent_id, created_at
        FROM product_categories;

        DROP TABLE product_categories;

        ALTER TABLE product_categories_new
        RENAME TO product_categories;
      `);
    });

    migrateCategories();

    console.log('Category migration completed.');
  } finally {
    db.pragma('foreign_keys = ON');
  }
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS
  idx_product_categories_name_parent
  ON product_categories (
    name COLLATE NOCASE,
    COALESCE(parent_id, 0)
  );
`);

db.prepare(`
  UPDATE orders
  SET created_at = CURRENT_TIMESTAMP
  WHERE created_at IS NULL OR created_at = ''
`).run();

db.prepare(`
  UPDATE orders
  SET status = 'Order Confirmed'
  WHERE status = 'Confirmed'
`).run();

db.prepare(`
  UPDATE orders
  SET status = 'Preparing'
  WHERE status = 'Processing'
`).run();

db.prepare(`
  UPDATE orders
  SET status = 'Dispatched'
  WHERE status = 'Shipped'
`).run();

db.prepare(`
  UPDATE orders
  SET status = 'Delivered'
  WHERE status = 'Completed'
`).run();

// =====================================
// DEFAULT STAFF POSITIONS
// =====================================

const defaultPositions = [
  'Manager',
  'Sales Assistant',
  'Stock Manager',
  'Order Manager',
  'Customer Support'
];

const insertPosition = db.prepare(`
  INSERT OR IGNORE INTO staff_positions (name)
  VALUES (?)
`);

for (const position of defaultPositions) {
  insertPosition.run(position);
}

// =====================================
// INITIAL CHAIRMAN ACCOUNT
// =====================================

// First startup creates the Chairman account using .env.
// After that, the database account is used for login.

const initialChairmanUsername =
  process.env.ADMIN_USERNAME || 'Dilshan';

const initialChairmanPassword =
  process.env.ADMIN_PASSWORD || '123456';

const existingChairman = db.prepare(`
  SELECT id
  FROM chairman_account
  WHERE id = 1
`).get();

if (!existingChairman) {
  const initialPasswordHash = bcrypt.hashSync(
    initialChairmanPassword,
    12
  );

  db.prepare(`
    INSERT INTO chairman_account (
      id,
      full_name,
      username,
      email,
      phone,
      password_hash,
      profile_image
    )
    VALUES (1, ?, ?, '', '', ?, '')
  `).run(
    'Chairman',
    initialChairmanUsername,
    initialPasswordHash
  );

  console.log(
    'Initial Chairman account created from environment settings.'
  );
}

// =====================================
// INITIAL CATEGORY AND PRODUCTS
// =====================================

db.prepare(`
  INSERT OR IGNORE INTO product_categories
    (name, parent_id)
  VALUES ('Traditional Mask', NULL)
`).run();

const traditionalCategory = db.prepare(`
  SELECT id
  FROM product_categories
  WHERE name = 'Traditional Mask' COLLATE NOCASE
    AND parent_id IS NULL
`).get();

function getOrCreateSubcategory(name, parentId) {
  const cleanName = String(name || '').trim();

  if (!cleanName || !parentId) {
    throw new Error('Invalid subcategory details.');
  }

  let row = db.prepare(`
    SELECT id
    FROM product_categories
    WHERE name = ? COLLATE NOCASE
      AND parent_id = ?
  `).get(cleanName, parentId);

  if (row) {
    return row.id;
  }

  try {
    const result = db.prepare(`
      INSERT INTO product_categories (name, parent_id)
      VALUES (?, ?)
    `).run(cleanName, parentId);

    return Number(result.lastInsertRowid);
  } catch (error) {
    row = db.prepare(`
      SELECT id
      FROM product_categories
      WHERE name = ? COLLATE NOCASE
        AND parent_id = ?
    `).get(cleanName, parentId);

    if (row) {
      return row.id;
    }

    throw error;
  }
}

const fireMaskSubcategory = getOrCreateSubcategory(
  'Fire Mask',
  traditionalCategory.id
);

const peacockMaskSubcategory = getOrCreateSubcategory(
  'Peacock Mask',
  traditionalCategory.id
);

function seedProduct(product) {
  const exists = db.prepare(
    `SELECT id FROM products WHERE slug = ?`
  ).get(product.slug);

  if (exists) {
    return;
  }

  db.prepare(`
    INSERT INTO products (
      slug,
      name,
      description,
      price,
      category_id,
      subcategory_id,
      size,
      colours_json,
      sizes_json,
      images_json,
      active,
      status,
      stock_quantity    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'Active', 100)
  `).run(
    product.slug,
    product.name,
    product.description || '',
    product.price,
    traditionalCategory.id,
    product.subcategoryId || null,
    product.size || '',
    JSON.stringify(product.colours || []),
    JSON.stringify(product.sizes || []),
    JSON.stringify(product.images || [])
  );
}

seedProduct({
  slug: 'fire-mask',
  name: '8" Traditional Fire Mask',
  description: 'A traditional-inspired Fire Mask featuring colourful hand-painted details.',
  price: 3800,
  subcategoryId: fireMaskSubcategory,
  size: '8 inches',
  colours: ['Red & Black', 'Yellow & Orange'],
  images: [
    '/assets/traditional-fire-mask-red.png',
    '/assets/traditional-fire-mask-yellow.png'
  ]
});

seedProduct({
  slug: 'traditional-peacock-mask',
  name: 'Traditional Peacock Mask',
  description: 'A colourful traditional Peacock Mask inspired by Sri Lankan craftsmanship.',
  price: 2200,
  subcategoryId: peacockMaskSubcategory,
  sizes: [
    { size: '6"', price: 2200 },
    { size: '8"', price: 3800 },
    { size: '10"', price: 5000 }
  ],
  images: [
    '/assets/traditional-peacock-mask-1.jpg',
    '/assets/traditional-peacock-mask-2.jpg'
  ]
});

db.prepare(`
  UPDATE products
  SET subcategory_id = ?
  WHERE slug = 'fire-mask'
    AND category_id = ?
`).run(
  fireMaskSubcategory,
  traditionalCategory.id
);

db.prepare(`
  UPDATE products
  SET subcategory_id = ?
  WHERE slug = 'traditional-peacock-mask'
    AND category_id = ?
`).run(
  peacockMaskSubcategory,
  traditionalCategory.id
);

// =====================================
// SESSION
// =====================================

const SQLiteStore = SQLiteStoreFactory(session);

app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: dataDir
  }),
  secret: process.env.SESSION_SECRET ||
    'change-this-ceyloria-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// =====================================
// RATE LIMITS
// =====================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const trackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

// =====================================
// EMAIL
// =====================================

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 465),
  secure: Number(process.env.SMTP_PORT || 465) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const ownerEmail = process.env.OWNER_EMAIL ||
  process.env.SMTP_USER ||
  'vihangadilshan0705@gmail.com';

const baseUrl = (
  process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`
).replace(/\/$/, '');

function emailConfigured() {
  return Boolean(
    process.env.SMTP_USER && process.env.SMTP_PASS
  );
}

async function sendMail(options) {
  if (!emailConfigured()) {
    console.log(
      'EMAIL NOT CONFIGURED: Check SMTP_USER and SMTP_PASS in .env'
    );
    return false;
  }

  try {
    await transporter.sendMail({
      from: `"Ceyloria Souvenirs" <${process.env.SMTP_USER}>`,
      ...options
    });

    return true;
  } catch (error) {
    console.error('Email error:', error.message);
    return false;
  }
}

// =====================================
// HELPER FUNCTIONS
// =====================================

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function normalizePhone(value) {
  let digits = String(value || '').replace(/\D/g, '');

  if (digits.startsWith('94')) {
    digits = digits.slice(2);
  }

  if (digits.startsWith('0')) {
    digits = digits.slice(1);
  }

  return digits;
}

function parseJson(value, fallback = []) {
  try {
    return JSON.parse(
      value || JSON.stringify(fallback)
    );
  } catch {
    return fallback;
  }
}

function makeSlug(value) {
  return String(value || 'product')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '') || 'product';
}

function uniqueSlug(name, currentId = null) {
  const base = makeSlug(name);
  let slug = base;
  let count = 1;

  while (true) {
    const existing = db.prepare(
      `SELECT id FROM products WHERE slug = ?`
    ).get(slug);

    if (!existing || existing.id === currentId) {
      return slug;
    }

    slug = `${base}-${count++}`;
  }
}

const productSelect = `
  SELECT
    p.*,
    main.name AS category_name,
    sub.name AS subcategory_name
  FROM products p
  LEFT JOIN product_categories main
    ON main.id = p.category_id
  LEFT JOIN product_categories sub
    ON sub.id = p.subcategory_id
`;

function productOutput(row) {
  const status = String(
    row.status || (row.active ? 'Active' : 'Inactive')
  );

  return {
    dbId: row.id,
    productId: Number(row.id),
    id: row.slug,
    slug: row.slug,
    name: row.name,
    description: row.description || '',
    price: Number(row.price || 0),
    discountPrice:
      row.discount_price === null ||
      row.discount_price === undefined
        ? null
        : Number(row.discount_price),    material: row.material || '',
    stockQuantity: Number(row.stock_quantity || 0),
    status,
    categoryId: row.category_id,
    category: row.category_name || '',
    subcategoryId: row.subcategory_id,
    subcategory: row.subcategory_name || '',
    size: row.size || '',
    colours: parseJson(row.colours_json),
    sizes: parseJson(row.sizes_json),
    images: parseJson(row.images_json),
    active: status.toLowerCase() === 'active',
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function getProductById(id) {
  return db.prepare(
    `${productSelect} WHERE p.id = ?`
  ).get(id);
}

function getProductBySlug(slug) {
  return db.prepare(
    `${productSelect} WHERE p.slug = ?`
  ).get(slug);
}

function deleteUploadedImages(images) {
  for (const image of images) {
    if (
      typeof image !== 'string' ||
      !image.startsWith('/uploads/products/')
    ) {
      continue;
    }

    const filename = path.basename(image);
    const filePath = path.join(uploadDir, filename);

    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (error) {
        console.error(
          'Image delete error:',
          error.message
        );
      }
    }
  }
}

function deleteProfileImage(image) {
  if (
    typeof image !== 'string' ||
    !image.startsWith('/uploads/profiles/')
  ) {
    return;
  }

  const filename = path.basename(image);
  const filePath = path.join(profileUploadDir, filename);

  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (error) {
      console.error(
        'Profile image delete error:',
        error.message
      );
    }
  }
}

async function sendWelcomeEmail(customer) {
  const html = `
    <div style="font-family:Arial;padding:25px;color:#10243d">
      <h2 style="color:#d4ad58">Welcome to Ceyloria!</h2>
      <p>Hello ${escapeHtml(customer.name)},</p>
      <p>Your Ceyloria customer account has been created successfully.</p>
      <p>Thank you for joining us.</p>
      <p><b>Ceyloria Souvenirs</b></p>
    </div>
  `;

  return sendMail({
    to: customer.email,
    subject: 'Welcome to Ceyloria Souvenirs',
    html
  });
}

// =====================================
// STAFF HELPER FUNCTIONS
// =====================================

function cleanPermissions(value) {
  let permissions = value;

  if (typeof permissions === 'string') {
    permissions = parseJson(permissions, []);
  }

  if (!Array.isArray(permissions)) {
    return [];
  }

  return [
    ...new Set(
      permissions.filter(permission =>
        ALL_STAFF_PERMISSIONS.includes(permission)
      )
    )
  ];
}

function getChairman() {
  return db.prepare(`
    SELECT
      id,
      full_name AS fullName,
      username,
      email,
      phone,
      profile_image AS profileImage,
      updated_at AS updatedAt
    FROM chairman_account
    WHERE id = 1
  `).get();
}

function getStaffById(id) {
  return db.prepare(`
    SELECT
      id,
      full_name AS fullName,
      username,
      email,
      phone,
      position,
      profile_image AS profileImage,
      permissions_json AS permissionsJson,
      active,
      created_at AS createdAt,
      updated_at AS updatedAt
    FROM staff
    WHERE id = ?
  `).get(id);
}

function staffOutput(row) {
  if (!row) return null;

  return {
    id: row.id,
    fullName: row.fullName,
    username: row.username,
    email: row.email || '',
    phone: row.phone || '',
    position: row.position || 'Staff',
    profileImage: row.profileImage || '',
    permissions: cleanPermissions(row.permissionsJson),
    active: Boolean(row.active),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt
  };
}

function usernameAlreadyExists(username, excludeStaffId = null) {
  const cleanUsername = String(username || '').trim();

  if (!cleanUsername) return true;

  const chairman = db.prepare(`
    SELECT id
    FROM chairman_account
    WHERE username = ? COLLATE NOCASE
  `).get(cleanUsername);

  if (chairman) return true;

  const staff = db.prepare(`
    SELECT id
    FROM staff
    WHERE username = ? COLLATE NOCASE
      AND (? IS NULL OR id != ?)
  `).get(
    cleanUsername,
    excludeStaffId,
    excludeStaffId
  );

  return Boolean(staff);
}

function validEmailOrEmpty(email) {
  if (!email) return true;

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPhoneOrEmpty(phone) {
  if (!phone) return true;

  return /^[0-9+\-\s()]{6,25}$/.test(phone);
}

// =====================================
// AUTHENTICATION MIDDLEWARE
// =====================================

function requireCustomer(req, res, next) {
  if (!req.session.customerId) {
    return res.status(401).json({
      error: 'Please login to continue.'
    });
  }

  next();
}

function requireChairman(req, res, next) {
  if (
    !req.session.isAdmin ||
    req.session.adminType !== 'chairman'
  ) {
    return res.status(403).json({
      error: 'Chairman access required.'
    });
  }

  const chairman = db.prepare(`
    SELECT id
    FROM chairman_account
    WHERE id = 1
  `).get();

  if (!chairman || req.session.adminId !== 1) {
    return res.status(401).json({
      error: 'Please login again.'
    });
  }

  next();
}

function permissionForAdminPath(pathname) {  if (pathname.startsWith('/api/admin/staff')) {
    return 'chairman-only';
  }

  if (
    pathname === '/api/admin/profile' ||
    pathname === '/api/admin/profile/password'
  ) {
    return 'profile';
  }

  if (pathname === '/api/admin/summary') {
    return 'dashboard';
  }

  if (
    pathname.startsWith('/api/admin/products') ||
    pathname.startsWith('/api/admin/categories')
  ) {
    return 'products';
  }

  if (pathname.startsWith('/api/admin/orders')) {
    return 'orders';
  }

  if (pathname.startsWith('/api/admin/customers')) {
    return 'customers';
  }

  if (pathname.startsWith('/api/admin/stock')) {
    return 'stock';
  }

  if (pathname.startsWith('/api/admin/invoices')) {
    return 'invoices';
  }

  return 'unknown';
}

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    return res.status(401).json({
      error: 'Admin login required.'
    });
  }

  if (req.session.adminType === 'chairman') {
    const chairman = db.prepare(`
      SELECT id
      FROM chairman_account
      WHERE id = 1
    `).get();

    if (!chairman || req.session.adminId !== 1) {
      return res.status(401).json({
        error: 'Please login again.'
      });
    }

    return next();
  }

  if (req.session.adminType !== 'staff') {
    return res.status(401).json({
      error: 'Please login again.'
    });
  }

  const staff = db.prepare(`
    SELECT id, active, permissions_json
    FROM staff
    WHERE id = ?
  `).get(req.session.adminId);

  if (!staff || !staff.active) {
    return res.status(401).json({
      error: 'Your staff account is inactive or unavailable.'
    });
  }

  const permission = permissionForAdminPath(
    req.path
  );

  if (permission === 'chairman-only') {
    return res.status(403).json({
      error: 'Only the Chairman can access Staff Management.'
    });
  }

  if (permission === 'profile') {
    return next();
  }

  const permissions = cleanPermissions(
    staff.permissions_json
  );

  if (
    permission === 'unknown' ||
    !permissions.includes(permission)
  ) {
    return res.status(403).json({
      error: 'You do not have permission to access this section.'
    });
  }

  next();
}

// =====================================
// PUBLIC PRODUCTS API
// =====================================

app.get('/api/products', (req, res) => {
  try {
    const rows = db.prepare(`
      ${productSelect}
      WHERE p.active = 1
        AND LOWER(p.status) = 'active'
      ORDER BY p.id DESC
    `).all();

    const categories = db.prepare(`
      SELECT id, name, parent_id AS parentId
      FROM product_categories
      ORDER BY name COLLATE NOCASE
    `).all();

    res.set('Cache-Control', 'no-store');

    res.json({
      success: true,
      products: rows.map(productOutput),
      categories
    });
  } catch (error) {
    console.error('Public products error:', error);

    res.status(500).json({
      success: false,
      error: 'Unable to load products.'
    });
  }
});

app.get('/api/products/:slug', (req, res) => {
  const product = getProductBySlug(
    String(req.params.slug)
  );

  if (
    !product ||
    !product.active ||
    String(product.status).toLowerCase() !== 'active'
  ) {
    return res.status(404).json({
      error: 'Product not found.'
    });
  }

  res.json({
    success: true,
    product: productOutput(product)
  });
});

// =====================================
// CUSTOMER SESSION
// =====================================

app.get('/api/auth/me', (req, res) => {
  if (!req.session.customerId) {
    return res.json({
      loggedIn: false,
      customer: null
    });
  }

  const customer = db.prepare(`
    SELECT id, name, phone, email, address, created_at
    FROM customers
    WHERE id = ?
  `).get(req.session.customerId);

  res.json({
    loggedIn: Boolean(customer),
    customer: customer || null
  });
});

// =====================================
// CUSTOMER REGISTER
// =====================================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const phone = String(req.body.phone || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const address = String(req.body.address || '').trim();
    const password = String(req.body.password || '');

    if (!name || !phone || !email || !address || !password) {
      return res.status(400).json({
        error: 'Please complete all required fields.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password must contain at least 6 characters.'
      });
    }

    const existing = db.prepare(
      `SELECT id FROM customers WHERE email = ?`
    ).get(email);

    if (existing) {
      return res.status(409).json({
        error: 'This email is already registered.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO customers (
        name,
        phone,
        email,
        address,
        password_hash,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(
      name,
      phone,
      email,
      address,
      passwordHash
    );

    const customerId = Number(result.lastInsertRowid);

    req.session.customerId = customerId;    const customer = {
      id: customerId,
      name,
      phone,
      email,
      address
    };

    const emailSent = await sendWelcomeEmail(customer);

    db.prepare(`
      UPDATE customers
      SET registration_email_sent = ?,
          welcome_email_sent = ?
      WHERE id = ?
    `).run(
      emailSent ? 1 : 0,
      emailSent ? 1 : 0,
      customerId
    );

    res.json({
      success: true,
      message: 'Account created successfully.',
      customer
    });
  } catch (error) {
    console.error('Registration error:', error);

    res.status(500).json({
      error: 'Unable to create account.'
    });
  }
});

// =====================================
// CUSTOMER FORGOT PASSWORD
// =====================================

app.post('/api/auth/forgot-password', passwordResetLimiter, async (req, res) => {
  const genericMessage =
    'If an account exists for that email, a password reset link will be sent.';

  try {
    const email = String(req.body.email || '')
      .trim()
      .toLowerCase();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(200).json({
        success: true,
        message: genericMessage
      });
    }

    const customer = db.prepare(`
      SELECT id, name, email
      FROM customers
      WHERE LOWER(email) = LOWER(?)
    `).get(email);

    // Always return the same response so account emails cannot be enumerated.
    if (!customer) {
      return res.json({
        success: true,
        message: genericMessage
      });
    }

    // Invalidate previous reset links before creating a new one.
    db.prepare(`
      DELETE FROM customer_password_resets
      WHERE customer_id = ?
    `).run(customer.id);

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    db.prepare(`
      INSERT INTO customer_password_resets (
        customer_id,
        token_hash,
        expires_at
      )
      VALUES (?, ?, datetime('now', '+20 minutes'))
    `).run(customer.id, tokenHash);

    const resetUrl =
      `${baseUrl}/login.html?reset=${encodeURIComponent(rawToken)}`;

    const emailSent = await sendMail({
      to: customer.email,
      subject: 'Reset your Ceyloria password',
      html: `
        <div style="font-family:Arial,sans-serif;color:#10243d;max-width:600px;margin:auto;padding:24px">
          <h2 style="color:#b58a36">Ceyloria Password Reset</h2>
          <p>Hello ${escapeHtml(customer.name)},</p>
          <p>We received a request to reset your Ceyloria account password.</p>
          <p>
            <a href="${escapeHtml(resetUrl)}"
              style="display:inline-block;background:#10243d;color:#fff;padding:13px 20px;text-decoration:none;border-radius:6px">
              Reset Password
            </a>
          </p>
          <p>This link expires in 20 minutes and can only be used once.</p>
          <p>If you did not request this, you can ignore this email.</p>
          <p>— Ceyloria Souvenirs</p>
        </div>
      `
    });

    if (!emailSent) {
      db.prepare(`
        DELETE FROM customer_password_resets
        WHERE customer_id = ?
      `).run(customer.id);
    }

    return res.json({
      success: true,
      message: genericMessage
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(200).json({
      success: true,
      message: genericMessage
    });
  }
});

// =====================================
// CUSTOMER RESET PASSWORD
// =====================================

app.post('/api/auth/reset-password', passwordResetLimiter, async (req, res) => {
  try {
    const token = String(req.body.token || '').trim();
    const password = String(req.body.password || '');

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(400).json({
        error: 'This password reset link is invalid or has expired.'
      });
    }

    if (password.length < 6 || password.length > 200) {
      return res.status(400).json({
        error: 'Password must contain between 6 and 200 characters.'
      });
    }

    const tokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const reset = db.prepare(`
      SELECT id, customer_id
      FROM customer_password_resets
      WHERE token_hash = ?
        AND expires_at > CURRENT_TIMESTAMP
    `).get(tokenHash);

    if (!reset) {
      return res.status(400).json({
        error: 'This password reset link is invalid or has expired.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const completeReset = db.transaction(() => {
      const stillValid = db.prepare(`
        SELECT id, customer_id
        FROM customer_password_resets
        WHERE id = ?
          AND token_hash = ?
          AND expires_at > CURRENT_TIMESTAMP
      `).get(reset.id, tokenHash);

      if (!stillValid) {
        throw new Error('RESET_LINK_EXPIRED');
      }

      db.prepare(`
        UPDATE customers
        SET password_hash = ?
        WHERE id = ?
      `).run(passwordHash, reset.customer_id);

      db.prepare(`
        DELETE FROM customer_password_resets
        WHERE customer_id = ?
      `).run(reset.customer_id);
    });

    completeReset();

    return res.json({
      success: true,
      message: 'Your password has been reset. Please log in with your new password.'
    });
  } catch (error) {
    if (error.message === 'RESET_LINK_EXPIRED') {
      return res.status(400).json({
        error: 'This password reset link is invalid or has expired.'
      });
    }

    console.error('Reset password error:', error);
    return res.status(500).json({
      error: 'Unable to reset your password. Please try again.'
    });
  }
});

// =====================================
// CUSTOMER LOGIN
// =====================================

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '')
      .trim()
      .toLowerCase();

    const password = String(req.body.password || '');

    const customer = db.prepare(
      `SELECT * FROM customers WHERE email = ?`
    ).get(email);

    if (!customer) {
      return res.status(401).json({
        error: 'Invalid email or password.'
      });
    }

    const valid = await bcrypt.compare(
      password,
      customer.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'Invalid email or password.'
      });
    }

    req.session.customerId = customer.id;

    res.json({
      success: true,
      message: 'Login successful.',
      customer: {
        id: customer.id,
        name: customer.name,
        phone: customer.phone,
        email: customer.email,
        address: customer.address
      }
    });
  } catch (error) {
    console.error('Login error:', error);

    res.status(500).json({
      error: 'Unable to login.'
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        error: 'Unable to logout.'
      });
    }

    res.clearCookie('connect.sid');

    res.json({ success: true });
  });
});

// =====================================
// CUSTOMER PROFILE
// =====================================

app.patch('/api/account/profile', requireCustomer, (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const phone = String(req.body.phone || '').trim();
    const address = String(req.body.address || '').trim();

    if (!name || !phone || !address) {
      return res.status(400).json({
        success: false,
        message: 'Please enter your name, phone number and delivery address.'
      });
    }

    const result = db.prepare(`
      UPDATE customers
      SET name = ?, phone = ?, address = ?
      WHERE id = ?
    `).run(
      name,
      phone,
      address,
      req.session.customerId
    );

    if (!result.changes) {
      return res.status(404).json({
        success: false,
        message: 'Customer account not found.'
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully.'
    });
  } catch (error) {
    console.error('Profile update error:', error);

    res.status(500).json({
      success: false,
      message: 'Could not update profile.'
    });
  }
});

// =====================================
// CUSTOMER ORDERS
// =====================================

app.get('/api/account/orders', requireCustomer, (req, res) => {
  try {
    const customer = db.prepare(`
      SELECT id, name, phone, email, address
      FROM customers
      WHERE id = ?
    `).get(req.session.customerId);

    if (!customer) {
      return res.status(401).json({
        success: false,
        message: 'Please login again.'
      });
    }

    const orders = db.prepare(`
      SELECT
        order_number,
        invoice_token,
        items_json,
        subtotal,
        status,
        created_at,
        address,
        payment
      FROM orders
      WHERE LOWER(email) = LOWER(?)
      ORDER BY id DESC
    `).all(customer.email);

    res.json({
      success: true,
      orders: orders.map(order => ({
        orderNumber: order.order_number,
        trackingUrl: '/track.html?token=' +
          encodeURIComponent(order.invoice_token),
        invoiceUrl: '/invoice.html?token=' +
          encodeURIComponent(order.invoice_token),
        items: parseJson(order.items_json),
        total: order.subtotal,
        status: order.status,
        date: order.created_at,
        address: order.address,
        payment: order.payment
      }))
    });
  } catch (error) {
    console.error('Customer orders error:', error);

    res.status(500).json({
      success: false,
      message: 'Could not load your orders.'
    });
  }
});

// =====================================
// INVOICE DATA AND HTML
// =====================================

function invoiceData(row) {
  const savedItems = parseJson(row.items_json);
  const items = savedItems.map(item => {
    let product = null;

    if (Number.isInteger(Number(item.productId))) {
      product = db.prepare(`
        SELECT id, name, images_json
        FROM products
        WHERE id = ?
      `).get(Number(item.productId));
    }

    if (!product && item.id) {
      product = db.prepare(`
        SELECT id, name, images_json
        FROM products
        WHERE slug = ?
      `).get(String(item.id));
    }

    const images = product
      ? parseJson(product.images_json)
      : [];

    return {
      ...item,
      productId: Number(item.productId || product?.id || 0) || null,
      name: item.name || product?.name || 'Product',
      image: item.image || images[0] || ''
    };
  });

  return {
    orderNumber: row.order_number,
    createdAt: row.created_at,
    name: row.customer_name,
    phone: row.phone,
    email: row.email,
    address: row.address,
    payment: row.payment,
    country: row.country,
    notes: row.notes,
    items,
    subtotal: row.subtotal,
    status: row.status
  };
}

function invoiceHtml(data) {
  const items = data.items.map(item => `
    <tr>
      <td style="padding:10px;border-bottom:1px solid #ddd">
        ${item.image ? `<img src="${escapeHtml(item.image)}" alt="" style="width:64px;height:64px;object-fit:cover;border-radius:8px;vertical-align:middle;margin-right:10px">` : ''}
        ${escapeHtml(item.name)}
        <div style="font-size:12px;color:#666">Product ID: ${Number(item.productId || 0) || 'Unavailable'}${item.size ? ` · Size: ${escapeHtml(item.size)}` : ''}${item.colour ? ` · Colour: ${escapeHtml(item.colour)}` : ''}</div>
      </td>
      <td style="padding:10px;border-bottom:1px solid #ddd">
        ${Number(item.quantity || 1)}
      </td>
      <td style="padding:10px;border-bottom:1px solid #ddd">
        Rs. ${Number(item.price || 0).toLocaleString()}
      </td>
      <td style="padding:10px;border-bottom:1px solid #ddd">
        Rs. ${Number(item.total || (Number(item.price || 0) * Number(item.quantity || 1))).toLocaleString()}
      </td>
    </tr>
  `).join('');

  return `
    <div style="font-family:Arial;color:#10243d;max-width:700px;margin:auto">      <h1 style="color:#d4ad58">CEYLORIA</h1>
      <h2>Order Invoice</h2>
      <p><b>Order Number:</b> ${escapeHtml(data.orderNumber)}</p>
      <p><b>Customer:</b> ${escapeHtml(data.name)}</p>
      <p><b>Phone:</b> ${escapeHtml(data.phone)}</p>
      <p><b>Email:</b> ${escapeHtml(data.email)}</p>
      <p><b>Delivery Address:</b> ${escapeHtml(data.address)}</p>
      <p><b>Payment:</b> ${escapeHtml(data.payment)}</p>
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr>
            <th align="left">Product</th>
            <th align="left">Quantity</th>
            <th align="left">Unit Price</th>
            <th align="left">Total</th>
          </tr>
        </thead>
        <tbody>${items}</tbody>
      </table>
      <h3>Total: Rs. ${Number(data.subtotal).toLocaleString()}</h3>
      <p>Thank you for shopping with Ceyloria Souvenirs.</p>
    </div>
  `;
}

// =====================================
// ORDER EMAILS
// =====================================

async function sendOrderEmails(row, data, invoiceUrl, trackingUrl) {
  const html = `
    <div style="font-family:Arial;color:#10243d;padding:20px">
      <h2 style="color:#d4ad58">Ceyloria Order Received</h2>
      <p><b>Order:</b> ${escapeHtml(data.orderNumber)}</p>
      <p><b>Customer:</b> ${escapeHtml(data.name)}</p>
      <p><b>Phone:</b> ${escapeHtml(data.phone)}</p>
      <p><b>Email:</b> ${escapeHtml(data.email)}</p>
      <p><b>Address:</b> ${escapeHtml(data.address)}</p>
      <p><b>Payment:</b> ${escapeHtml(data.payment)}</p>
      <p><b>Total:</b> Rs. ${Number(data.subtotal).toLocaleString()}</p>
      <p><b>Order Status:</b> ${escapeHtml(data.status)}</p>
      <p>
        <a href="${escapeHtml(invoiceUrl)}"
          style="background:#10243d;color:white;padding:12px 18px;text-decoration:none">
          View Invoice
        </a>
      </p>
      <p>
        <a href="${escapeHtml(trackingUrl)}"
          style="background:#d4ad58;color:#10243d;padding:12px 18px;text-decoration:none">
          Track Your Order
        </a>
      </p>
    </div>
  `;

  const ownerSent = await sendMail({
    to: ownerEmail,
    subject: `New Ceyloria Order - ${data.orderNumber}`,
    html
  });

  const customerSent = await sendMail({
    to: data.email,
    subject: `Your Ceyloria Order - ${data.orderNumber}`,
    html
  });

  db.prepare(`
    UPDATE orders
    SET email_owner_sent = ?,
        email_customer_sent = ?
    WHERE id = ?
  `).run(
    ownerSent ? 1 : 0,
    customerSent ? 1 : 0,
    row.id
  );

  return { ownerSent, customerSent };
}

// =====================================
// CREATE ORDER + AUTOMATIC STOCK UPDATE
// =====================================

app.post('/api/orders', requireCustomer, async (req, res) => {
  try {
    const customer = db.prepare(`
      SELECT *
      FROM customers
      WHERE id = ?
    `).get(req.session.customerId);

    if (!customer) {
      return res.status(401).json({
        error: 'Please login again.'
      });
    }

    const body = req.body || {};
    const items = Array.isArray(body.items) ? body.items : [];

    if (!items.length) {
      return res.status(400).json({
        error: 'Your cart is empty.'
      });
    }

    const orderNumber = 'CEY-' +
      new Date().toISOString().slice(0, 10).replace(/-/g, '') +
      '-' +
      crypto.randomBytes(3).toString('hex').toUpperCase();

    const token = crypto.randomBytes(32).toString('hex');

    const createOrderTransaction = db.transaction(() => {
      const safeItems = [];
      const quantitiesByProduct = new Map();
      let subtotal = 0;

      for (const item of items) {
        const productId = String(
          item.id || item.productId || ''
        );

        const product = getProductBySlug(productId);

        if (
          !product ||
          !product.active ||
          String(product.status).toLowerCase() !== 'active'
        ) {
          throw new Error('Invalid product in cart.');
        }

        const quantityNumber = Number(item.quantity || 1);

        if (
          !Number.isFinite(quantityNumber) ||
          !Number.isInteger(quantityNumber) ||
          quantityNumber < 1 ||
          quantityNumber > 100
        ) {
          throw new Error('Invalid product quantity.');
        }

        const quantity = quantityNumber;
        const selectedSize = String(item.size || '');
        const availableSizes = parseJson(product.sizes_json);

        let unitPrice = Number(product.price);

        if (availableSizes.length) {
          const selected = availableSizes.find(
            size => String(size.size) === selectedSize
          );

          if (!selected) {
            throw new Error(
              'Please select a valid product size.'
            );
          }

          unitPrice = Number(selected.price);
        } else if (
          product.discount_price !== null &&
          product.discount_price !== undefined &&
          Number(product.discount_price) > 0
        ) {
          unitPrice = Number(product.discount_price);
        }

        if (
          !Number.isFinite(unitPrice) ||
          unitPrice < 0
        ) {
          throw new Error('Invalid product price.');
        }

        const colour = String(
          item.colour || item.color || ''
        );

        const lineTotal = unitPrice * quantity;
        subtotal += lineTotal;

        safeItems.push({
          id: product.slug,
          productId: Number(product.id),
          name: product.name,
          image: parseJson(product.images_json)[0] || '',
          price: unitPrice,
          quantity,
          total: lineTotal,
          colour,
          size: selectedSize
        });

        const previousQuantity =
          quantitiesByProduct.get(product.id) || 0;

        quantitiesByProduct.set(
          product.id,
          previousQuantity + quantity
        );
      }

      for (const [productId, totalQuantity] of quantitiesByProduct) {
        const product = db.prepare(`
          SELECT id, name, stock_quantity
          FROM products
          WHERE id = ?
        `).get(productId);

        if (!product) {
          throw new Error(
            'A product in your cart no longer exists.'
          );
        }

        const availableStock = Number(
          product.stock_quantity || 0
        );

        if (availableStock < totalQuantity) {
          throw new Error(
            `Not enough stock for "${product.name}". Available stock: ${availableStock}.`
          );
        }
      }

      for (const [productId, totalQuantity] of quantitiesByProduct) {
        db.prepare(`
          UPDATE products
          SET stock_quantity = stock_quantity - ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(totalQuantity, productId);
      }

      const result = db.prepare(`
        INSERT INTO orders (
          order_number,
          invoice_token,
          customer_name,
          phone,
          email,
          address,
          payment,
          country,
          notes,
          items_json,          subtotal,
          status,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).run(
        orderNumber,
        token,
        customer.name,
        customer.phone,
        customer.email,
        customer.address || '',
        String(body.payment || 'Cash on Delivery'),
        String(body.country || 'Sri Lanka'),
        String(body.notes || ''),
        JSON.stringify(safeItems),
        subtotal,
        'Pending'
      );

      return {
        orderId: Number(result.lastInsertRowid),
        subtotal
      };
    });

    const orderResult = createOrderTransaction();

    const row = db.prepare(`
      SELECT *
      FROM orders
      WHERE id = ?
    `).get(orderResult.orderId);

    const data = invoiceData(row);
    const invoiceUrl =
      `${baseUrl}/invoice.html?token=${token}`;

    const trackingUrl =
      `${baseUrl}/track.html?token=${token}`;

    const emailStatus = await sendOrderEmails(
      row,
      data,
      invoiceUrl,
      trackingUrl
    );

    res.json({
      success: true,
      orderNumber,
      invoiceToken: token,
      invoiceUrl,
      trackingUrl,
      emailStatus
    });
  } catch (error) {
    console.error('Order error:', error);

    const isExpectedError = [
      'Invalid product in cart.',
      'Invalid product quantity.',
      'Please select a valid product size.',
      'Invalid product price.',
      'Your cart is empty.'
    ].includes(error.message) ||
      String(error.message).startsWith('Not enough stock') ||
      String(error.message).startsWith('A product in your cart');

    res.status(isExpectedError ? 400 : 500).json({
      error: isExpectedError
        ? error.message
        : 'Unable to place your order.'
    });
  }
});

// =====================================
// INVOICE API
// =====================================

app.get('/api/invoice/:token', (req, res) => {
  const token = String(req.params.token || '');

  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return res.status(404).json({
      error: 'Invalid invoice link.'
    });
  }

  const row = db.prepare(`
    SELECT *
    FROM orders
    WHERE invoice_token = ?
  `).get(token);

  if (!row) {
    return res.status(404).json({
      error: 'Invoice not found.'
    });
  }

  res.json(invoiceData(row));
});

// =====================================
// TRACKING API
// =====================================

app.get('/api/track/:token', trackLimiter, (req, res) => {
  const token = String(req.params.token || '');

  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return res.status(404).json({
      error: 'Tracking link is invalid.'
    });
  }

  const row = db.prepare(`
    SELECT order_number, created_at, status, address
    FROM orders
    WHERE invoice_token = ?
  `).get(token);

  if (!row) {
    return res.status(404).json({
      error: 'Order not found.'
    });
  }

  res.set('Cache-Control', 'no-store');

  res.json({
    orderNumber: row.order_number,
    createdAt: row.created_at,
    status: row.status,
    address: row.address
  });
});

app.post('/api/track/order', trackLimiter, (req, res) => {
  try {
    const orderNumber = String(
      req.body.orderNumber || ''
    ).trim().toUpperCase();

    const phone = normalizePhone(req.body.phone);

    if (!orderNumber || !phone) {
      return res.status(400).json({
        error: 'Please enter your order number and phone number.'
      });
    }

    const row = db.prepare(`
      SELECT order_number, created_at, status, address, phone
      FROM orders
      WHERE UPPER(order_number) = ?
    `).get(orderNumber);

    if (!row || normalizePhone(row.phone) !== phone) {
      return res.status(404).json({
        error: 'Order number or phone number is incorrect.'
      });
    }

    res.set('Cache-Control', 'no-store');

    res.json({
      success: true,
      orderNumber: row.order_number,
      createdAt: row.created_at,
      status: row.status,
      address: row.address
    });
  } catch (error) {
    console.error('Order tracking error:', error);

    res.status(500).json({
      error: 'Unable to track your order. Please try again.'
    });
  }
});

// =====================================
// ADMIN LOGIN STATUS
// =====================================

app.get('/api/admin/me', (req, res) => {
  if (!req.session.isAdmin) {
    return res.json({
      loggedIn: false,
      adminType: null,
      admin: null
    });
  }

  if (req.session.adminType === 'chairman') {
    const chairman = getChairman();

    if (!chairman) {
      return res.json({
        loggedIn: false,
        adminType: null,
        admin: null
      });
    }

    return res.json({
      loggedIn: true,
      adminType: 'chairman',
      admin: chairman,
      permissions: ['all']
    });
  }

  if (req.session.adminType === 'staff') {
    const staff = db.prepare(`
      SELECT *
      FROM staff
      WHERE id = ?
        AND active = 1
    `).get(req.session.adminId);

    if (!staff) {
      return res.json({
        loggedIn: false,
        adminType: null,
        admin: null
      });
    }

    return res.json({
      loggedIn: true,
      adminType: 'staff',
      admin: staffOutput({
        id: staff.id,
        fullName: staff.full_name,
        username: staff.username,
        email: staff.email,
        phone: staff.phone,
        position: staff.position,
        profileImage: staff.profile_image,
        permissionsJson: staff.permissions_json,
        active: staff.active,
        createdAt: staff.created_at,
        updatedAt: staff.updated_at
      }),
      permissions: cleanPermissions(
        staff.permissions_json      )
    });
  }

  res.json({
    loggedIn: false,
    adminType: null,
    admin: null
  });
});

// =====================================
// ADMIN LOGIN
// =====================================

app.post('/api/admin/login', authLimiter, async (req, res) => {
  try {
    const username = String(
      req.body.username || ''
    ).trim();

    const password = String(
      req.body.password || ''
    );

    if (!username || !password) {
      return res.status(400).json({
        error: 'Please enter your username and password.'
      });
    }

    // Check Chairman account first.
    const chairman = db.prepare(`
      SELECT *
      FROM chairman_account
      WHERE username = ? COLLATE NOCASE
        AND id = 1
    `).get(username);

    if (chairman) {
      const valid = await bcrypt.compare(
        password,
        chairman.password_hash
      );

      if (!valid) {
        return res.status(401).json({
          error: 'Incorrect username or password.'
        });
      }

      return req.session.regenerate(error => {
        if (error) {
          console.error('Session error:', error);

          return res.status(500).json({
            error: 'Unable to create admin session.'
          });
        }

        req.session.isAdmin = true;
        req.session.adminType = 'chairman';
        req.session.adminId = 1;

        req.session.save(saveError => {
          if (saveError) {
            console.error('Session save error:', saveError);

            return res.status(500).json({
              error: 'Unable to save admin session.'
            });
          }

          res.json({
            success: true,
            message: 'Chairman login successful.',
            adminType: 'chairman'
          });
        });
      });
    }

    // If not Chairman, check staff account.
    const staff = db.prepare(`
      SELECT *
      FROM staff
      WHERE username = ? COLLATE NOCASE
        AND active = 1
    `).get(username);

    if (!staff) {
      return res.status(401).json({
        error: 'Incorrect username or password.'
      });
    }

    const valid = await bcrypt.compare(
      password,
      staff.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'Incorrect username or password.'
      });
    }

    req.session.regenerate(error => {
      if (error) {
        console.error('Session error:', error);

        return res.status(500).json({
          error: 'Unable to create admin session.'
        });
      }

      req.session.isAdmin = true;
      req.session.adminType = 'staff';
      req.session.adminId = staff.id;

      req.session.save(saveError => {
        if (saveError) {
          console.error('Session save error:', saveError);

          return res.status(500).json({
            error: 'Unable to save admin session.'
          });
        }

        res.json({
          success: true,
          message: 'Staff login successful.',
          adminType: 'staff'
        });
      });
    });
  } catch (error) {
    console.error('Admin login error:', error);

    res.status(500).json({
      error: 'Unable to login.'
    });
  }
});

// =====================================
// ADMIN LOGOUT
// =====================================

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        error: 'Unable to logout.'
      });
    }

    res.clearCookie('connect.sid');

    res.json({
      success: true
    });
  });
});

// =====================================
// PROFILE IMAGE UPLOAD HELPER
// =====================================

function saveProfileImage(dataUrl) {
  if (!dataUrl) {
    return '';
  }

  const match = String(dataUrl).match(
    /^data:(image\/(?:jpeg|jpg|png|webp));base64,([A-Za-z0-9+/=\s]+)$/i
  );

  if (!match) {
    throw new Error(
      'Please select a JPG, PNG or WEBP profile image.'
    );
  }

  const mime = match[1].toLowerCase();

  const buffer = Buffer.from(
    match[2].replace(/\s/g, ''),
    'base64'
  );

  if (
    !buffer.length ||
    buffer.length > 2 * 1024 * 1024
  ) {
    throw new Error(
      'Profile image must be smaller than 2MB.'
    );
  }

  const isJpeg =
    buffer.length >= 3 &&
    buffer[0] === 0xFF &&
    buffer[1] === 0xD8 &&
    buffer[2] === 0xFF;

  const isPng =
    buffer.length >= 8 &&
    buffer.subarray(0, 8).equals(
      Buffer.from([
        137, 80, 78, 71, 13, 10, 26, 10
      ])
    );

  const isWebp =
    buffer.length >= 12 &&
    buffer.toString('ascii', 0, 4) === 'RIFF' &&
    buffer.toString('ascii', 8, 12) === 'WEBP';

  let extension = '';

  if (
    (mime === 'image/jpeg' || mime === 'image/jpg') &&
    isJpeg
  ) {
    extension = '.jpg';
  } else if (mime === 'image/png' && isPng) {
    extension = '.png';
  } else if (mime === 'image/webp' && isWebp) {
    extension = '.webp';
  } else {
    throw new Error(
      'Image content and image format do not match.'
    );
  }

  const filename =
    crypto.randomBytes(16).toString('hex') + extension;

  fs.writeFileSync(
    path.join(profileUploadDir, filename),
    buffer
  );

  return '/uploads/profiles/' + filename;
}

// =====================================
// GET CURRENT ADMIN PROFILE
// =====================================

app.get('/api/admin/profile', requireAdmin, (req, res) => {  if (req.session.adminType === 'chairman') {
    const chairman = getChairman();

    if (!chairman) {
      return res.status(404).json({
        error: 'Chairman account not found.'
      });
    }

    return res.json({
      success: true,
      adminType: 'chairman',
      profile: chairman
    });
  }

  const staff = db.prepare(`
    SELECT
      id,
      full_name AS fullName,
      username,
      email,
      phone,
      position,
      profile_image AS profileImage,
      permissions_json AS permissionsJson,
      active,
      created_at AS createdAt,
      updated_at AS updatedAt
    FROM staff
    WHERE id = ?
      AND active = 1
  `).get(req.session.adminId);

  if (!staff) {
    return res.status(404).json({
      error: 'Staff account not found.'
    });
  }

  res.json({
    success: true,
    adminType: 'staff',
    profile: staffOutput(staff)
  });
});

// =====================================
// UPDATE CURRENT ADMIN PROFILE
// =====================================

app.patch('/api/admin/profile', requireAdmin, (req, res) => {
  let newProfileImage = '';

  try {
    const fullName = String(
      req.body.fullName || ''
    ).trim();

    const username = String(
      req.body.username || ''
    ).trim();

    const email = String(
      req.body.email || ''
    ).trim().toLowerCase();

    const phone = String(
      req.body.phone || ''
    ).trim();

    if (
      !fullName ||
      fullName.length > 120 ||
      !username ||
      username.length < 3 ||
      username.length > 40
    ) {
      return res.status(400).json({
        error: 'Please enter a valid name and username.'
      });
    }

    if (!validEmailOrEmpty(email)) {
      return res.status(400).json({
        error: 'Please enter a valid email address.'
      });
    }

    if (!validPhoneOrEmpty(phone)) {
      return res.status(400).json({
        error: 'Please enter a valid phone number.'
      });
    }

    const imageData = req.body.profileImage;

    if (
      imageData &&
      String(imageData).startsWith('data:')
    ) {
      newProfileImage = saveProfileImage(imageData);
    }

    if (req.session.adminType === 'chairman') {
      const duplicateStaff = db.prepare(`
        SELECT id
        FROM staff
        WHERE username = ? COLLATE NOCASE
      `).get(username);

      if (duplicateStaff) {
        if (newProfileImage) {
          deleteProfileImage(newProfileImage);
        }

        return res.status(409).json({
          error: 'This username is already used by a staff member.'
        });
      }

      const old = db.prepare(`
        SELECT profile_image
        FROM chairman_account
        WHERE id = 1
      `).get();

      const profileImage = newProfileImage ||
        old.profile_image ||
        '';

      db.prepare(`
        UPDATE chairman_account
        SET full_name = ?,
            username = ?,
            email = ?,
            phone = ?,
            profile_image = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `).run(
        fullName,
        username,
        email,
        phone,
        profileImage
      );

      if (
        newProfileImage &&
        old.profile_image &&
        old.profile_image !== newProfileImage
      ) {
        deleteProfileImage(old.profile_image);
      }

      return res.json({
        success: true,
        message: 'Chairman profile updated successfully.',
        profile: getChairman()
      });
    }

    const staffId = req.session.adminId;

    if (usernameAlreadyExists(username, staffId)) {
      if (newProfileImage) {
        deleteProfileImage(newProfileImage);
      }

      return res.status(409).json({
        error: 'This username is already in use.'
      });
    }

    const old = db.prepare(`
      SELECT profile_image
      FROM staff
      WHERE id = ?
        AND active = 1
    `).get(staffId);

    if (!old) {
      if (newProfileImage) {
        deleteProfileImage(newProfileImage);
      }

      return res.status(404).json({
        error: 'Staff account not found.'
      });
    }

    const profileImage = newProfileImage ||
      old.profile_image ||
      '';

    db.prepare(`
      UPDATE staff
      SET full_name = ?,
          username = ?,
          email = ?,
          phone = ?,
          profile_image = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND active = 1
    `).run(
      fullName,
      username,
      email,
      phone,
      profileImage,
      staffId
    );

    if (
      newProfileImage &&
      old.profile_image &&
      old.profile_image !== newProfileImage
    ) {
      deleteProfileImage(old.profile_image);
    }

    res.json({
      success: true,
      message: 'Profile updated successfully.'
    });
  } catch (error) {
    if (newProfileImage) {
      deleteProfileImage(newProfileImage);
    }

    console.error('Admin profile update error:', error);

    res.status(400).json({
      error: error.message || 'Unable to update profile.'
    });
  }
});

// =====================================
// CHANGE CURRENT ADMIN PASSWORD
// =====================================

app.patch(
  '/api/admin/profile/password',
  requireAdmin,
  async (req, res) => {    try {
      const currentPassword = String(
        req.body.currentPassword || ''
      );

      const newPassword = String(
        req.body.newPassword || ''
      );

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          error: 'Please enter your current and new passwords.'
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          error: 'New password must contain at least 8 characters.'
        });
      }

      if (req.session.adminType === 'chairman') {
        const chairman = db.prepare(`
          SELECT password_hash
          FROM chairman_account
          WHERE id = 1
        `).get();

        if (!chairman) {
          return res.status(404).json({
            error: 'Chairman account not found.'
          });
        }

        const valid = await bcrypt.compare(
          currentPassword,
          chairman.password_hash
        );

        if (!valid) {
          return res.status(401).json({
            error: 'Current password is incorrect.'
          });
        }

        const passwordHash = await bcrypt.hash(
          newPassword,
          12
        );

        db.prepare(`
          UPDATE chairman_account
          SET password_hash = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = 1
        `).run(passwordHash);

        return res.json({
          success: true,
          message: 'Chairman password updated successfully.'
        });
      }

      const staff = db.prepare(`
        SELECT password_hash
        FROM staff
        WHERE id = ?
          AND active = 1
      `).get(req.session.adminId);

      if (!staff) {
        return res.status(404).json({
          error: 'Staff account not found.'
        });
      }

      const valid = await bcrypt.compare(
        currentPassword,
        staff.password_hash
      );

      if (!valid) {
        return res.status(401).json({
          error: 'Current password is incorrect.'
        });
      }

      const passwordHash = await bcrypt.hash(
        newPassword,
        12
      );

      db.prepare(`
        UPDATE staff
        SET password_hash = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        passwordHash,
        req.session.adminId
      );

      res.json({
        success: true,
        message: 'Password updated successfully.'
      });
    } catch (error) {
      console.error('Password update error:', error);

      res.status(500).json({
        error: 'Unable to update password.'
      });
    }
  }
);

// =====================================
// STAFF POSITIONS - LIST
// CHAIRMAN ONLY
// =====================================

app.get(
  '/api/admin/staff/positions',
  requireChairman,
  (req, res) => {
    const positions = db.prepare(`
      SELECT id, name, created_at AS createdAt
      FROM staff_positions
      ORDER BY name COLLATE NOCASE
    `).all();

    res.json({
      success: true,
      positions
    });
  }
);

// =====================================
// STAFF POSITIONS - CREATE
// =====================================

app.post(
  '/api/admin/staff/positions',
  requireChairman,
  (req, res) => {
    try {
      const name = String(
        req.body.name || ''
      ).trim();

      if (!name || name.length > 80) {
        return res.status(400).json({
          error: 'Please enter a valid position name.'
        });
      }

      const existing = db.prepare(`
        SELECT id
        FROM staff_positions
        WHERE name = ? COLLATE NOCASE
      `).get(name);

      if (existing) {
        return res.status(409).json({
          error: 'This position already exists.'
        });
      }

      const result = db.prepare(`
        INSERT INTO staff_positions (name)
        VALUES (?)
      `).run(name);

      res.json({
        success: true,
        position: {
          id: Number(result.lastInsertRowid),
          name
        }
      });
    } catch (error) {
      console.error('Create position error:', error);

      res.status(500).json({
        error: 'Unable to create position.'
      });
    }
  }
);

// =====================================
// STAFF POSITIONS - EDIT
// =====================================

app.put(
  '/api/admin/staff/positions/:id',
  requireChairman,
  (req, res) => {
    try {
      const id = Number(req.params.id);
      const name = String(
        req.body.name || ''
      ).trim();

      if (
        !Number.isInteger(id) ||
        id < 1 ||
        !name ||
        name.length > 80
      ) {
        return res.status(400).json({
          error: 'Invalid position details.'
        });
      }

      const existing = db.prepare(`
        SELECT id
        FROM staff_positions
        WHERE name = ? COLLATE NOCASE
          AND id != ?
      `).get(name, id);

      if (existing) {
        return res.status(409).json({
          error: 'This position name is already in use.'
        });
      }

      const old = db.prepare(`
        SELECT name
        FROM staff_positions
        WHERE id = ?
      `).get(id);

      if (!old) {
        return res.status(404).json({
          error: 'Position not found.'
        });
      }

      const update = db.transaction(() => {
        db.prepare(`
          UPDATE staff_positions
          SET name = ?
          WHERE id = ?
        `).run(name, id);

        db.prepare(`
          UPDATE staff          SET position = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE position = ?
        `).run(name, old.name);
      });

      update();

      res.json({
        success: true,
        message: 'Position updated successfully.'
      });
    } catch (error) {
      console.error('Update position error:', error);

      res.status(500).json({
        error: 'Unable to update position.'
      });
    }
  }
);

// =====================================
// STAFF POSITIONS - DELETE
// =====================================

app.delete(
  '/api/admin/staff/positions/:id',
  requireChairman,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
          error: 'Invalid position ID.'
        });
      }

      const position = db.prepare(`
        SELECT id, name
        FROM staff_positions
        WHERE id = ?
      `).get(id);

      if (!position) {
        return res.status(404).json({
          error: 'Position not found.'
        });
      }

      const assigned = db.prepare(`
        SELECT COUNT(*) AS total
        FROM staff
        WHERE position = ?
      `).get(position.name).total;

      if (assigned > 0) {
        return res.status(400).json({
          error: 'This position is assigned to staff members. Change their positions first.'
        });
      }

      db.prepare(`
        DELETE FROM staff_positions
        WHERE id = ?
      `).run(id);

      res.json({
        success: true,
        message: 'Position deleted successfully.'
      });
    } catch (error) {
      console.error('Delete position error:', error);

      res.status(500).json({
        error: 'Unable to delete position.'
      });
    }
  }
);

// =====================================
// STAFF LIST
// CHAIRMAN ONLY
// =====================================

app.get(
  '/api/admin/staff',
  requireChairman,
  (req, res) => {
    try {
      const rows = db.prepare(`
        SELECT
          id,
          full_name AS fullName,
          username,
          email,
          phone,
          position,
          profile_image AS profileImage,
          permissions_json AS permissionsJson,
          active,
          created_at AS createdAt,
          updated_at AS updatedAt
        FROM staff
        ORDER BY id DESC
      `).all();

      res.json({
        success: true,
        staff: rows.map(staffOutput),
        permissionOptions: STAFF_PERMISSION_NAMES
      });
    } catch (error) {
      console.error('Staff list error:', error);

      res.status(500).json({
        error: 'Unable to load staff members.'
      });
    }
  }
);

// =====================================
// CREATE STAFF ACCOUNT
// CHAIRMAN ONLY
// =====================================

app.post(
  '/api/admin/staff',
  requireChairman,
  async (req, res) => {
    try {
      const fullName = String(
        req.body.fullName || ''
      ).trim();

      const username = String(
        req.body.username || ''
      ).trim();

      const email = String(
        req.body.email || ''
      ).trim().toLowerCase();

      const phone = String(
        req.body.phone || ''
      ).trim();

      const position = String(
        req.body.position || ''
      ).trim();

      const password = String(
        req.body.password || ''
      );

      const permissions = cleanPermissions(
        req.body.permissions
      );

      if (
        !fullName ||
        fullName.length > 120 ||
        !username ||
        username.length < 3 ||
        username.length > 40 ||
        !password ||
        password.length < 8 ||
        !position
      ) {
        return res.status(400).json({
          error: 'Please complete all required staff details. Password must contain at least 8 characters.'
        });
      }

      if (!validEmailOrEmpty(email)) {
        return res.status(400).json({
          error: 'Please enter a valid email address.'
        });
      }

      if (!validPhoneOrEmpty(phone)) {
        return res.status(400).json({
          error: 'Please enter a valid phone number.'
        });
      }

      if (usernameAlreadyExists(username)) {
        return res.status(409).json({
          error: 'This username is already in use.'
        });
      }

      const validPosition = db.prepare(`
        SELECT id
        FROM staff_positions
        WHERE name = ? COLLATE NOCASE
      `).get(position);

      if (!validPosition) {
        return res.status(400).json({
          error: 'Please select a valid staff position.'
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const result = db.prepare(`
        INSERT INTO staff (
          full_name,
          username,
          email,
          phone,
          position,
          password_hash,
          permissions_json,
          active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
      `).run(
        fullName,
        username,
        email,
        phone,
        position,
        passwordHash,
        JSON.stringify(permissions)
      );

      res.json({
        success: true,
        message: 'Staff account created successfully.',
        staff: staffOutput(
          getStaffById(Number(result.lastInsertRowid))
        )
      });
    } catch (error) {
      console.error('Create staff error:', error);

      res.status(500).json({
        error: 'Unable to create staff account.'
      });
    }
  }
);// =====================================
// EDIT STAFF ACCOUNT
// CHAIRMAN ONLY
// =====================================

app.put(
  '/api/admin/staff/:id',
  requireChairman,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
          error: 'Invalid staff ID.'
        });
      }

      const oldStaff = db.prepare(`
        SELECT *
        FROM staff
        WHERE id = ?
      `).get(id);

      if (!oldStaff) {
        return res.status(404).json({
          error: 'Staff member not found.'
        });
      }

      const fullName = String(
        req.body.fullName || ''
      ).trim();

      const username = String(
        req.body.username || ''
      ).trim();

      const email = String(
        req.body.email || ''
      ).trim().toLowerCase();

      const phone = String(
        req.body.phone || ''
      ).trim();

      const position = String(
        req.body.position || ''
      ).trim();

      const permissions = cleanPermissions(
        req.body.permissions
      );

      const active = req.body.active === false ||
        req.body.active === 0 ||
        req.body.active === '0'
          ? 0
          : 1;

      const newPassword = String(
        req.body.password || ''
      );

      if (
        !fullName ||
        fullName.length > 120 ||
        !username ||
        username.length < 3 ||
        username.length > 40 ||
        !position
      ) {
        return res.status(400).json({
          error: 'Please enter valid staff details.'
        });
      }

      if (!validEmailOrEmpty(email)) {
        return res.status(400).json({
          error: 'Please enter a valid email address.'
        });
      }

      if (!validPhoneOrEmpty(phone)) {
        return res.status(400).json({
          error: 'Please enter a valid phone number.'
        });
      }

      if (usernameAlreadyExists(username, id)) {
        return res.status(409).json({
          error: 'This username is already in use.'
        });
      }

      const validPosition = db.prepare(`
        SELECT id
        FROM staff_positions
        WHERE name = ? COLLATE NOCASE
      `).get(position);

      if (!validPosition) {
        return res.status(400).json({
          error: 'Please select a valid staff position.'
        });
      }

      if (newPassword && newPassword.length < 8) {
        return res.status(400).json({
          error: 'New password must contain at least 8 characters.'
        });
      }

      let passwordHash = oldStaff.password_hash;

      if (newPassword) {
        passwordHash = await bcrypt.hash(
          newPassword,
          12
        );
      }

      db.prepare(`
        UPDATE staff
        SET full_name = ?,
            username = ?,
            email = ?,
            phone = ?,
            position = ?,
            password_hash = ?,
            permissions_json = ?,
            active = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        fullName,
        username,
        email,
        phone,
        position,
        passwordHash,
        JSON.stringify(permissions),
        active,
        id
      );

      res.json({
        success: true,
        message: 'Staff member updated successfully.',
        staff: staffOutput(getStaffById(id))
      });
    } catch (error) {
      console.error('Update staff error:', error);

      res.status(500).json({
        error: 'Unable to update staff member.'
      });
    }
  }
);

// =====================================
// DELETE STAFF ACCOUNT
// CHAIRMAN ONLY
// =====================================

app.delete(
  '/api/admin/staff/:id',
  requireChairman,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
          error: 'Invalid staff ID.'
        });
      }

      const staff = db.prepare(`
        SELECT id, profile_image
        FROM staff
        WHERE id = ?
      `).get(id);

      if (!staff) {
        return res.status(404).json({
          error: 'Staff member not found.'
        });
      }

      db.prepare(`
        DELETE FROM staff
        WHERE id = ?
      `).run(id);

      deleteProfileImage(staff.profile_image);

      res.json({
        success: true,
        message: 'Staff account deleted successfully.'
      });
    } catch (error) {
      console.error('Delete staff error:', error);

      res.status(500).json({
        error: 'Unable to delete staff account.'
      });
    }
  }
);

// =====================================
// ADMIN SUMMARY
// =====================================

app.get('/api/admin/summary', requireAdmin, (req, res) => {
  try {
    const totalOrders = db.prepare(
      `SELECT COUNT(*) AS n FROM orders`
    ).get().n;

    const pendingOrders = db.prepare(`
      SELECT COUNT(*) AS n
      FROM orders
      WHERE status = 'Pending'
    `).get().n;

    const totalCustomers = db.prepare(
      `SELECT COUNT(*) AS n FROM customers`
    ).get().n;

    const sales = db.prepare(`
      SELECT COALESCE(SUM(subtotal), 0) AS total
      FROM orders
      WHERE status != 'Cancelled'
    `).get().total;

    const totalProducts = db.prepare(`
      SELECT COUNT(*) AS n
      FROM products
    `).get().n;

    const lowStockProducts = db.prepare(`
      SELECT COUNT(*) AS n
      FROM products
      WHERE active = 1
        AND stock_quantity <= 5
    `).get().n;    res.json({
      totalOrders,
      pendingOrders,
      totalCustomers,
      sales,
      totalProducts,
      lowStockProducts
    });
  } catch (error) {
    console.error('Admin summary error:', error);

    res.status(500).json({
      error: 'Unable to load dashboard summary.'
    });
  }
});

// =====================================
// ADMIN CATEGORIES
// =====================================

app.get('/api/admin/categories', requireAdmin, (req, res) => {
  try {
    const categories = db.prepare(`
      SELECT
        c.id,
        c.name,
        c.parent_id AS parentId,
        COUNT(DISTINCT p.id) AS productCount
      FROM product_categories c
      LEFT JOIN products p
        ON p.category_id = c.id
        OR p.subcategory_id = c.id
      GROUP BY c.id
      ORDER BY c.name COLLATE NOCASE
    `).all();

    res.json({
      success: true,
      categories
    });
  } catch (error) {
    console.error('Admin categories error:', error);

    res.status(500).json({
      error: 'Unable to load categories.'
    });
  }
});

// CREATE MAIN CATEGORY OR SUBCATEGORY

app.post('/api/admin/categories', requireAdmin, (req, res) => {
  try {
    const name = String(
      req.body.name || ''
    ).trim();

    const parentId =
      req.body.parentId === undefined ||
      req.body.parentId === null ||
      req.body.parentId === ''
        ? null
        : Number(req.body.parentId);

    if (!name || name.length > 80) {
      return res.status(400).json({
        error: 'Please enter a valid category name.'
      });
    }

    if (parentId !== null) {
      if (!Number.isInteger(parentId)) {
        return res.status(400).json({
          error: 'Invalid main category.'
        });
      }

      const parent = db.prepare(`
        SELECT id
        FROM product_categories
        WHERE id = ?
          AND parent_id IS NULL
      `).get(parentId);

      if (!parent) {
        return res.status(400).json({
          error: 'Selected main category does not exist.'
        });
      }
    }

    const existing = parentId === null
      ? db.prepare(`
          SELECT id, name, parent_id AS parentId
          FROM product_categories
          WHERE name = ? COLLATE NOCASE
            AND parent_id IS NULL
        `).get(name)
      : db.prepare(`
          SELECT id, name, parent_id AS parentId
          FROM product_categories
          WHERE name = ? COLLATE NOCASE
            AND parent_id = ?
        `).get(name, parentId);

    if (existing) {
      return res.json({
        success: true,
        category: existing,
        message: 'This category already exists.'
      });
    }

    const result = db.prepare(`
      INSERT INTO product_categories (name, parent_id)
      VALUES (?, ?)
    `).run(name, parentId);

    const category = db.prepare(`
      SELECT id, name, parent_id AS parentId
      FROM product_categories
      WHERE id = ?
    `).get(Number(result.lastInsertRowid));

    res.json({
      success: true,
      category
    });
  } catch (error) {
    console.error('Category create error:', error);

    res.status(500).json({
      error: 'Unable to create category.'
    });
  }
});

// EDIT CATEGORY NAME

app.put('/api/admin/categories/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const name = String(req.body.name || '').trim();

  if (
    !Number.isInteger(id) ||
    !name ||
    name.length > 80
  ) {
    return res.status(400).json({
      error: 'Invalid category details.'
    });
  }

  try {
    const result = db.prepare(`
      UPDATE product_categories
      SET name = ?
      WHERE id = ?
    `).run(name, id);

    if (!result.changes) {
      return res.status(404).json({
        error: 'Category not found.'
      });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(400).json({
      error: 'Category name may already exist under this parent.'
    });
  }
});

// DELETE CATEGORY

app.delete('/api/admin/categories/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return res.status(400).json({
      error: 'Invalid category ID.'
    });
  }

  try {
    const category = db.prepare(`
      SELECT id, parent_id
      FROM product_categories
      WHERE id = ?
    `).get(id);

    if (!category) {
      return res.status(404).json({
        error: 'Category not found.'
      });
    }

    if (category.parent_id === null) {
      const children = db.prepare(`
        SELECT COUNT(*) AS total
        FROM product_categories
        WHERE parent_id = ?
      `).get(id).total;

      if (children > 0) {
        return res.status(400).json({
          error: 'Please delete its subcategories first.'
        });
      }
    }

    db.prepare(`
      DELETE FROM product_categories
      WHERE id = ?
    `).run(id);

    res.json({ success: true });
  } catch (error) {
    console.error('Category delete error:', error);

    res.status(500).json({
      error: 'Unable to delete category.'
    });
  }
});

// =====================================
// ADMIN PRODUCTS - LIST
// =====================================

app.get('/api/admin/products', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`
      ${productSelect}
      ORDER BY p.id DESC
    `).all();

    res.json({
      success: true,
      products: rows.map(productOutput)
    });
  } catch (error) {
    console.error('Admin products error:', error);

    res.status(500).json({
      error: 'Unable to load products.'
    });
  }
});// =====================================
// ADMIN IMAGE UPLOAD
// =====================================

app.post('/api/admin/products/upload', requireAdmin, (req, res) => {
  const uploaded = [];

  try {
    const files = Array.isArray(req.body.images)
      ? req.body.images
      : [req.body];

    if (!files.length || files.length > 8) {
      return res.status(400).json({
        error: 'Upload between 1 and 8 images.'
      });
    }

    for (const file of files) {
      const dataUrl = String(
        typeof file === 'string'
          ? file
          : (file?.data || file?.base64 || '')
      ).trim();

      const match = dataUrl.match(
        /^data:(image\/(?:jpeg|jpg|png|webp|gif));base64,([A-Za-z0-9+/=\s]+)$/i
      );

      if (!match) {
        throw new Error(
          'Invalid image data. Please select a JPG, PNG, WEBP or GIF image.'
        );
      }

      const mime = match[1].toLowerCase();

      const buffer = Buffer.from(
        match[2].replace(/\s/g, ''),
        'base64'
      );

      if (
        !buffer.length ||
        buffer.length > 5 * 1024 * 1024
      ) {
        throw new Error(
          'Each image must be smaller than 5MB.'
        );
      }

      const isJpeg =
        buffer.length >= 3 &&
        buffer[0] === 0xFF &&
        buffer[1] === 0xD8 &&
        buffer[2] === 0xFF;

      const isPng =
        buffer.length >= 8 &&
        buffer.subarray(0, 8).equals(
          Buffer.from([
            137, 80, 78, 71, 13, 10, 26, 10
          ])
        );

      const isGif =
        buffer.length >= 6 &&
        ['GIF87a', 'GIF89a'].includes(
          buffer.subarray(0, 6).toString('ascii')
        );

      const isWebp =
        buffer.length >= 12 &&
        buffer.toString('ascii', 0, 4) === 'RIFF' &&
        buffer.toString('ascii', 8, 12) === 'WEBP';

      let extension = '';

      if (
        (mime === 'image/jpeg' || mime === 'image/jpg') &&
        isJpeg
      ) {
        extension = '.jpg';
      } else if (mime === 'image/png' && isPng) {
        extension = '.png';
      } else if (mime === 'image/webp' && isWebp) {
        extension = '.webp';
      } else if (mime === 'image/gif' && isGif) {
        extension = '.gif';
      } else {
        throw new Error(
          'Image content and image format do not match.'
        );
      }

      const filename =
        crypto.randomBytes(16).toString('hex') + extension;

      fs.writeFileSync(
        path.join(uploadDir, filename),
        buffer
      );

      uploaded.push('/uploads/products/' + filename);
    }

    res.json({
      success: true,
      images: uploaded
    });
  } catch (error) {
    for (const image of uploaded) {
      deleteUploadedImages([image]);
    }

    console.error('Image upload error:', error);

    res.status(400).json({
      error: error.message || 'Unable to upload images.'
    });
  }
});

// =====================================
// PRODUCT VALIDATION
// =====================================

function validateProductBody(body) {
  const name = String(body.name || '').trim();
  const description = String(body.description || '').trim();
  const price = Number(body.price);
  const categoryId = Number(body.categoryId);

  const discountValue =
    body.discountPrice !== undefined
      ? body.discountPrice
      : body.discount_price;

  const discountPrice =
    discountValue === undefined ||
    discountValue === null ||
    discountValue === ''
      ? null
      : Number(discountValue);

  const material = String(body.material || '').trim();

  const stockValue =
    body.stockQuantity !== undefined
      ? body.stockQuantity
      : body.stock_quantity;

  const stockQuantity =
    stockValue === undefined || stockValue === ''
      ? 0
      : Number(stockValue);

  const rawStatus = String(
    body.status ||
    (body.active === false || body.active === 0
      ? 'Inactive'
      : 'Active')
  ).trim();

  const status =
    rawStatus.toLowerCase() === 'inactive'
      ? 'Inactive'
      : rawStatus.toLowerCase() === 'active'
        ? 'Active'
        : '';

  const subcategoryId =
    body.subcategoryId === undefined ||
    body.subcategoryId === null ||
    body.subcategoryId === ''
      ? null
      : Number(body.subcategoryId);

  const images = Array.isArray(body.images)
    ? body.images
    : [];

  const colours = Array.isArray(body.colours)
    ? body.colours
    : [];

  const sizes = Array.isArray(body.sizes)
    ? body.sizes
    : [];

  if (!name || name.length > 180) {
    throw new Error('Please enter a valid product name.');
  }

  if (
    !Number.isFinite(price) ||
    price < 0 ||
    price > 100000000
  ) {
    throw new Error('Please enter a valid product price.');
  }

  if (
    discountPrice !== null &&
    (
      !Number.isFinite(discountPrice) ||
      discountPrice < 0 ||
      discountPrice > price
    )
  ) {
    throw new Error(
      'Discount price must be valid and cannot be higher than the product price.'
    );
  }

  if (
    !Number.isInteger(stockQuantity) ||
    stockQuantity < 0 ||
    stockQuantity > 100000000
  ) {
    throw new Error(
      'Please enter a valid stock quantity.'
    );
  }

  if (!status) {
    throw new Error(
      'Please select Active or Inactive product status.'
    );
  }

  if (!Number.isInteger(categoryId) || categoryId < 1) {
    throw new Error('Please select a main category.');
  }

  const mainCategory = db.prepare(`
    SELECT id
    FROM product_categories
    WHERE id = ?
      AND parent_id IS NULL
  `).get(categoryId);

  if (!mainCategory) {
    throw new Error(
      'Selected main category does not exist.'
    );
  }

  if (subcategoryId !== null) {
    if (
      !Number.isInteger(subcategoryId) ||
      subcategoryId < 1
    ) {
      throw new Error('Please select a valid subcategory.');
    }

    const subcategory = db.prepare(`
      SELECT id
      FROM product_categories
      WHERE id = ?
        AND parent_id = ?
    `).get(subcategoryId, categoryId);

    if (!subcategory) {
      throw new Error(
        'Selected subcategory does not belong to this main category.'
      );
    }
  }

  if (images.length > 8) {
    throw new Error(
      'Maximum 8 images are allowed per product.'
    );
  }

  if (images.some(image =>
    typeof image !== 'string' ||
    !(
      image.startsWith('/assets/') ||
      image.startsWith('/uploads/products/')
    )
  )) {
    throw new Error('Invalid product image.');
  }

  const cleanSizes = sizes.map(item => ({
    size: String(item.size || '').trim(),
    price: Number(item.price)
  }));

  for (const item of cleanSizes) {
    if (
      !item.size ||
      !Number.isFinite(item.price) ||
      item.price < 0 ||
      item.price > 100000000
    ) {
      throw new Error(
        'Please check the product sizes and prices.'
      );
    }
  }

  return {
    name,
    description,
    price,
    discountPrice,
    material,
    stockQuantity,
    status,
    categoryId,
    subcategoryId,
    size: String(body.size || '').trim(),
    colours: colours
      .map(value => String(value).trim())
      .filter(Boolean),
    sizes: cleanSizes,
    images,
    active: status === 'Active' ? 1 : 0
  };
}

// =====================================
// CREATE PRODUCT
// =====================================

app.post('/api/admin/products', requireAdmin, (req, res) => {
  try {
    const product = validateProductBody(req.body);
    const slug = uniqueSlug(product.name);

    const result = db.prepare(`
      INSERT INTO products (
        slug,
        name,
        description,
        price,
        discount_price,
        material,
        stock_quantity,
        status,
        category_id,
        subcategory_id,
        size,
        colours_json,
        sizes_json,
        images_json,
        active,
        created_at,
        updated_at
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
      )
    `).run(
      slug,
      product.name,
      product.description,
      product.price,
      product.discountPrice,
      product.material,
      product.stockQuantity,
      product.status,
      product.categoryId,
      product.subcategoryId,
      product.size,
      JSON.stringify(product.colours),
      JSON.stringify(product.sizes),
      JSON.stringify(product.images),
      product.active
    );

    const saved = getProductById(
      Number(result.lastInsertRowid)
    );

    res.json({
      success: true,
      message: 'Product added successfully.',
      product: productOutput(saved)
    });
  } catch (error) {
    console.error('Create product error:', error);

    res.status(400).json({
      error: error.message || 'Unable to add product.'
    });
  }
});

// =====================================
// EDIT PRODUCT
// =====================================

app.put('/api/admin/products/:id', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: 'Invalid product ID.'
      });
    }

    const oldProduct = getProductById(id);

    if (!oldProduct) {
      return res.status(404).json({
        error: 'Product not found.'
      });
    }

    const product = validateProductBody(req.body);
    const slug = uniqueSlug(product.name, id);

    db.prepare(`
      UPDATE products
      SET slug = ?,
          name = ?,
          description = ?,
          price = ?,
          discount_price = ?,
          material = ?,
          stock_quantity = ?,
          status = ?,
          category_id = ?,
          subcategory_id = ?,
          size = ?,
          colours_json = ?,
          sizes_json = ?,
          images_json = ?,
          active = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      slug,
      product.name,
      product.description,
      product.price,
      product.discountPrice,
      product.material,
      product.stockQuantity,
      product.status,
      product.categoryId,
      product.subcategoryId,
      product.size,
      JSON.stringify(product.colours),
      JSON.stringify(product.sizes),
      JSON.stringify(product.images),
      product.active,
      id
    );

    const removedImages = parseJson(
      oldProduct.images_json
    ).filter(image => !product.images.includes(image));

    deleteUploadedImages(removedImages);

    res.json({
      success: true,
      message: 'Product updated successfully.',
      product: productOutput(getProductById(id))
    });
  } catch (error) {
    console.error('Update product error:', error);

    res.status(400).json({
      error: error.message || 'Unable to update product.'
    });
  }
});

// =====================================
// DELETE PRODUCT
// =====================================


// =====================================
// DELETE PRODUCT
// =====================================

app.delete('/api/admin/products/:id', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: 'Invalid product ID.'
      });
    }

    const product = getProductById(id);

    if (!product) {
      return res.status(404).json({
        error: 'Product not found.'
      });
    }

    deleteUploadedImages(
      parseJson(product.images_json)
    );

    db.prepare(`
      DELETE FROM products
      WHERE id = ?
    `).run(id);

    res.json({
      success: true,
      message: 'Product deleted successfully.'
    });
  } catch (error) {
    console.error('Delete product error:', error);

    res.status(500).json({
      error: 'Unable to delete product.'
    });
  }
});



// =====================================
// STOCK MANAGEMENT
// =====================================

app.get('/api/admin/stock', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`
      ${productSelect}
      ORDER BY p.stock_quantity ASC, p.name COLLATE NOCASE
    `).all();

    res.json({
      success: true,
      products: rows.map(productOutput)
    });
  } catch (error) {
    console.error('Stock list error:', error);

    res.status(500).json({
      error: 'Unable to load stock information.'
    });
  }
});

app.patch(
  '/api/admin/stock/:id',
  requireAdmin,
  (req, res) => {
    try {
      const id = Number(req.params.id);
      const stockQuantity = Number(
        req.body.stockQuantity
      );

      if (
        !Number.isInteger(id) ||
        id < 1 ||
        !Number.isInteger(stockQuantity) ||
        stockQuantity < 0 ||
        stockQuantity > 100000000
      ) {
        return res.status(400).json({
          error: 'Please enter a valid stock quantity.'
        });
      }

      const result = db.prepare(`
        UPDATE products
        SET stock_quantity = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(stockQuantity, id);

      if (!result.changes) {
        return res.status(404).json({
          error: 'Product not found.'
        });
      }

      res.json({
        success: true,
        stockQuantity
      });
    } catch (error) {
      console.error('Stock update error:', error);

      res.status(500).json({
        error: 'Unable to update stock.'
      });
    }
  }
);

// =====================================
// ADMIN CUSTOMERS
// =====================================

app.get('/api/admin/customers', requireAdmin, (req, res) => {
  try {
    const customers = db.prepare(`
      SELECT
        id,
        name,
        phone,
        email,
        address,
        created_at
      FROM customers
      ORDER BY id DESC
    `).all();

    res.json(customers);
  } catch (error) {
    console.error('Admin customers error:', error);

    res.status(500).json({
      error: 'Unable to load customers.'
    });
  }
});

app.delete('/api/admin/customers/:id', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: 'Invalid customer ID.'
      });
    }

    db.prepare(`
      DELETE FROM customers
      WHERE id = ?
    `).run(id);

    res.json({ success: true });
  } catch (error) {
    console.error('Delete customer error:', error);

    res.status(500).json({
      error: 'Unable to delete customer.'
    });
  }
});

// =====================================
// ADMIN ORDERS
// =====================================

app.get('/api/admin/orders', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT *
      FROM orders
      ORDER BY id DESC
    `).all();

    const orders = rows.map(row => ({
      ...invoiceData(row),
      id: row.id,
      emailOwnerSent: Boolean(row.email_owner_sent),
      emailCustomerSent: Boolean(row.email_customer_sent),
      invoiceToken: row.invoice_token
    }));

    res.json(orders);
  } catch (error) {
    console.error('Admin orders error:', error);

    res.status(500).json({
      error: 'Unable to load orders.'
    });
  }
});

// =====================================
// UPDATE ORDER STATUS
// =====================================

app.patch(
  '/api/admin/orders/:id/status',
  requireAdmin,
  (req, res) => {
    const id = Number(req.params.id);
    const status = String(req.body.status || '');

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error: 'Invalid order ID.'
      });
    }

    if (!ORDER_STATUSES.includes(status)) {
      return res.status(400).json({
        error: 'Invalid order status.'
      });
    }

    const result = db.prepare(`
      UPDATE orders
      SET status = ?
      WHERE id = ?
    `).run(status, id);

    if (!result.changes) {
      return res.status(404).json({
        error: 'Order not found.'
      });
    }

    res.json({
      success: true,
      status
    });
  }
);

// =====================================
// DELETE ORDER
// =====================================

app.delete('/api/admin/orders/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({
      error: 'Invalid order ID.'
    });
  }

  try {
    const deleteOrderTransaction = db.transaction(() => {
      const order = db.prepare(`
        SELECT id, items_json
        FROM orders
        WHERE id = ?
      `).get(id);

      if (!order) {
        return false;
      }

      const quantitiesByProduct = new Map();
      const items = parseJson(order.items_json);

      for (const item of items) {
        let productId = Number(item.productId || 0);

        if (!Number.isInteger(productId) || productId < 1) {
          const slug = String(item.id || item.slug || '');
          if (slug) {
            const product = db.prepare(`
              SELECT id
              FROM products
              WHERE slug = ?
            `).get(slug);
            productId = Number(product?.id || 0);
          }
        }

        const quantity = Number(item.quantity || item.qty || 1);

        if (
          productId > 0 &&
          Number.isInteger(quantity) &&
          quantity > 0
        ) {
          quantitiesByProduct.set(
            productId,
            (quantitiesByProduct.get(productId) || 0) + quantity
          );
        }
      }

      for (const [productId, quantity] of quantitiesByProduct) {
        db.prepare(`
          UPDATE products
          SET stock_quantity = stock_quantity + ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(quantity, productId);
      }

      db.prepare(`
        DELETE FROM orders
        WHERE id = ?
      `).run(id);

      return true;
    });

    const deleted = deleteOrderTransaction();

    if (!deleted) {
      return res.status(404).json({
        error: 'Order not found.'
      });
    }

    return res.json({
      success: true,
      message: 'Order deleted and available product stock restored.'
    });
  } catch (error) {
    console.error('Delete order and restore stock error:', error);

    return res.status(500).json({
      error: 'Unable to delete order and restore stock.'
    });
  }
});

// =====================================
// ADMIN INVOICE VIEW (AUTHENTICATED)
// =====================================

app.get('/api/admin/orders/:id/invoice', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).send('Invalid order ID.');
    }

    const row = db.prepare(`
      SELECT *
      FROM orders
      WHERE id = ?
    `).get(id);

    if (!row) {
      return res.status(404).send('Invoice not found.');
    }

    const data = invoiceData(row);
    const items = data.items.map(item => `
      <tr>
        <td style="padding:10px;border-bottom:1px solid #ddd">
          ${item.image ? `<img src="${escapeHtml(item.image)}" alt="" style="width:64px;height:64px;object-fit:cover;border-radius:8px;vertical-align:middle;margin-right:10px">` : ''}
          ${escapeHtml(item.name)}
          <div style="font-size:12px;color:#666">Product ID: ${Number(item.productId || 0) || 'Unavailable'}${item.size ? ` · Size: ${escapeHtml(item.size)}` : ''}${item.colour ? ` · Colour: ${escapeHtml(item.colour)}` : ''}</div>
        </td>
        <td style="padding:10px;border-bottom:1px solid #ddd">${Number(item.quantity || 1)}</td>
        <td style="padding:10px;border-bottom:1px solid #ddd">Rs. ${Number(item.price || 0).toLocaleString()}</td>
        <td style="padding:10px;border-bottom:1px solid #ddd">Rs. ${Number(item.total || (Number(item.price || 0) * Number(item.quantity || 1))).toLocaleString()}</td>
      </tr>
    `).join('');
    res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ceyloria Invoice ${escapeHtml(data.orderNumber)}</title>
<style>
body{margin:0;padding:28px;background:#f4f6f8;font-family:Arial,sans-serif;color:#10243d}
.invoice{max-width:850px;margin:auto;background:#fff;padding:34px;border-radius:14px;box-shadow:0 8px 30px #10243d18}
button{background:#10243d;color:#fff;border:0;border-radius:7px;padding:11px 18px;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:22px}
th{text-align:left;background:#f5f0e4;padding:12px}
@media print{body{padding:0;background:#fff}.invoice{box-shadow:none;border-radius:0;padding:0}.print-btn{display:none}}
</style>
</head>
<body><div class="invoice">
<div style="display:flex;justify-content:space-between;align-items:center;gap:16px">
<div><h1 style="color:#c49a43;margin:0">CEYLORIA</h1><p>Souvenirs & Gifts</p></div>
<button class="print-btn" onclick="window.print()">PRINT / SAVE PDF</button>
</div>
<h2>Order Invoice</h2>
<p><b>Order Number:</b> ${escapeHtml(data.orderNumber)}</p>
<p><b>Date:</b> ${escapeHtml(data.createdAt)}</p>
<p><b>Customer:</b> ${escapeHtml(data.name)}</p>
<p><b>Phone:</b> ${escapeHtml(data.phone)}</p>
<p><b>Email:</b> ${escapeHtml(data.email)}</p>
<p><b>Delivery Address:</b> ${escapeHtml(data.address)} ${escapeHtml(data.country || '')}</p>
<p><b>Payment:</b> ${escapeHtml(data.payment)}</p>
<p><b>Status:</b> ${escapeHtml(data.status)}</p>
<table><thead><tr><th>Product</th><th>Qty</th><th>Unit Price</th><th>Total</th></tr></thead>
<tbody>${items}</tbody></table>
<h2 style="text-align:right">Total: Rs. ${Number(data.subtotal || 0).toLocaleString()}</h2>
${data.notes ? `<p><b>Notes:</b> ${escapeHtml(data.notes)}</p>` : ''}
<p style="text-align:center;margin-top:34px">Thank you for shopping with Ceyloria Souvenirs.</p>
</div></body></html>`);
  } catch (error) {
    console.error('Admin invoice view error:', error);
    res.status(500).send('Unable to open invoice.');
  }
});

// =====================================
// ADMIN INVOICES
// =====================================

app.get('/api/admin/invoices', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT *
      FROM orders
      ORDER BY id DESC
    `).all();

    res.json({
      success: true,
      invoices: rows.map(row => ({
        ...invoiceData(row),
        id: row.id,
        invoiceToken: row.invoice_token
      }))
    });
  } catch (error) {
    console.error('Admin invoices error:', error);

    res.status(500).json({
      error: 'Unable to load invoices.'
    });
  }
});

// =====================================
// HEALTH CHECK
// =====================================

app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Ceyloria server is running.'
  });
});

// =====================================
// STATIC PAGES
// =====================================

app.get('/track.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'track.html'));
});

app.get('/invoice.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'invoice.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

app.get('/account.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'account.html'));
});

app.use(express.static(publicDir));

// =====================================
// START SERVER
// =====================================

app.listen(PORT, () => {
  console.log(
    `Ceyloria store running on port ${PORT}`
  );
});