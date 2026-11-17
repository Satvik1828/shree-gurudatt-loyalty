import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import express from 'express';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type VehicleType = 'car' | 'bike' | 'scooter' | 'commercial';
type WashEventType = 'paid_wash' | 'free_earned' | 'free_redeemed' | 'new_card';

interface WashEvent {
  id: string;
  customerId: string;
  customerName: string;
  customerPhone: string;
  type: WashEventType;
  vehicleType: VehicleType;
  stampsAfter: number;
  stampsRequired: number;
  createdAt: string;
  note?: string;
}

interface CustomerRecord {
  id: string;
  name: string;
  phone: string;
  vehicleType: VehicleType;
  stamps: number;
  freeWashesAvailable: number;
  totalPaidWashes: number;
  totalFreeWashes: number;
  cardsCompleted: number;
  status: 'active' | 'inactive';
  joinedAt: string;
  lastVisitAt: string;
}

interface ShopSettings {
  shopName: string;
  tagline: string;
  address: string;
  stampsRequired: number;
  supportPhone: string;
}

interface NotificationRecord {
  id: string;
  customerId: string;
  customerName: string;
  customerPhone: string;
  channel: 'sms' | 'in_app' | 'sms_and_app';
  title: string;
  message: string;
  deliveryStatus: 'sent' | 'delivered';
  provider: 'twilio' | 'gateway';
  read: boolean;
  createdAt: string;
}

interface StoreData {
  settings: ShopSettings;
  ownerPinHash: string | null;
  customers: CustomerRecord[];
  events: WashEvent[];
  notifications: NotificationRecord[];
}

interface OtpEntry {
  code: string;
  expiresAt: number;
}

const DATA_DIR = path.resolve(__dirname, 'data');
const STORE_PATH = path.join(DATA_DIR, 'loyalty-store.json');
const TOKEN_SECRET = process.env.SESSION_SECRET || 'sgwc-shivane-pune-loyalty-secret-2026';

const otpStore = new Map<string, OtpEntry>();

const VEHICLE_SERVICES = [
  {
    id: 'car' as VehicleType,
    label: 'Cars & SUVs',
    shortLabel: 'Cars',
    startingPrice: 350,
    washDuration: '30 min',
    description: 'High-pressure foam wash, underbody rinse, interior vacuum & tyre polish.',
  },
  {
    id: 'bike' as VehicleType,
    label: 'Motorcycles',
    shortLabel: 'Bikes',
    startingPrice: 120,
    washDuration: '15 min',
    description: 'Snow-foam degreasing, chain-safe pressure rinse & microfiber dry.',
  },
  {
    id: 'scooter' as VehicleType,
    label: 'Scooters & Mopeds',
    shortLabel: 'Scooters',
    startingPrice: 100,
    washDuration: '12 min',
    description: 'Gentle body shampoo, footboard detailing & matte-safe finish.',
  },
  {
    id: 'commercial' as VehicleType,
    label: 'All Vehicle Types',
    shortLabel: 'All Types',
    startingPrice: 450,
    washDuration: '40 min',
    description: 'Pickups, tempos, vans & fleet vehicles washed with industrial bays.',
  },
];

function hashPin(pin: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(pin, salt, 32).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPinHash(pin: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  const derived = crypto.scryptSync(pin, salt, 32);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

function normalizePhone(raw: string): string {
  const digits = String(raw || '').replace(/\D/g, '');
  if (digits.length === 12 && digits.startsWith('91')) {
    return digits.slice(2);
  }
  if (digits.length === 11 && digits.startsWith('0')) {
    return digits.slice(1);
  }
  return digits.slice(-10);
}

function isValidIndianPhone(phone: string): boolean {
  return /^[6-9]\d{9}$/.test(phone);
}

function extractPhoneFromQrOrQuery(input: string): string {
  const trimmed = String(input || '').trim();
  if (!trimmed) return '';

  const sgwcMatch = trimmed.match(/SGWC:CARD:(\d{10,12})/i);
  if (sgwcMatch) {
    return normalizePhone(sgwcMatch[1]);
  }

  try {
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      const url = new URL(trimmed);
      const param = url.searchParams.get('card') || url.searchParams.get('phone');
      if (param) return normalizePhone(param);
    }
  } catch {
    // Ignore URL parse error and fall through
  }

  return trimmed;
}

function signToken(payload: Record<string, string | number>): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token: string): Record<string, string | number> | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (parsed.exp && Date.now() > Number(parsed.exp)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function buildInitialStore(): StoreData {
  const envPin = process.env.OWNER_PIN?.trim();
  return {
    settings: {
      shopName: 'Shree Gurudatt Washing Center',
      tagline: 'Clean Vehicle... Happy Journey...',
      address: 'Pawana Nagar Road, Shivane, Maval, Pune - 410506',
      stampsRequired: 10,
      supportPhone: '+91 98765 43210',
    },
    ownerPinHash: envPin && /^\d{4,6}$/.test(envPin) ? hashPin(envPin) : null,
    customers: [],
    events: [],
    notifications: [],
  };
}

function loadStore(): StoreData {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(STORE_PATH)) {
    const initial = buildInitialStore();
    saveStore(initial);
    return initial;
  }
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as StoreData & { ownerPin?: string };
    // Migrate legacy plaintext ownerPin if present
    if (!parsed.ownerPinHash && parsed.ownerPin) {
      parsed.ownerPinHash = hashPin(parsed.ownerPin);
      delete parsed.ownerPin;
      saveStore(parsed);
    }
    if (!Array.isArray(parsed.customers)) parsed.customers = [];
    if (!Array.isArray(parsed.events)) parsed.events = [];
    if (!Array.isArray(parsed.notifications)) parsed.notifications = [];
    return parsed;
  } catch {
    const initial = buildInitialStore();
    saveStore(initial);
    return initial;
  }
}

function saveStore(data: StoreData): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  const tmpPath = `${STORE_PATH}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmpPath, STORE_PATH);
}

let store: StoreData = loadStore();

function isTwilioConfigured(): boolean {
  return Boolean(
    process.env.TWILIO_ACCOUNT_SID &&
      process.env.TWILIO_AUTH_TOKEN &&
      process.env.TWILIO_FROM_NUMBER,
  );
}

function computeKpis(data: StoreData) {
  const now = new Date();
  const currentMonth = now.getMonth();
  const currentYear = now.getFullYear();

  const totalCustomers = data.customers.length;
  const totalPaid = data.customers.reduce((sum, c) => sum + c.totalPaidWashes, 0);
  const totalFree = data.customers.reduce((sum, c) => sum + c.totalFreeWashes, 0);
  const totalWashes = totalPaid + totalFree;

  const eventsThisMonth = data.events.filter((ev) => {
    if (ev.type !== 'paid_wash' && ev.type !== 'free_redeemed') return false;
    const dt = new Date(ev.createdAt);
    return dt.getMonth() === currentMonth && dt.getFullYear() === currentYear;
  }).length;

  return {
    totalCustomers,
    totalWashes,
    freeWashes: totalFree,
    thisMonthWashes: eventsThisMonth,
  };
}

function computeVehicleBreakdown(data: StoreData) {
  const counts: Record<VehicleType, number> = {
    car: 0,
    bike: 0,
    scooter: 0,
    commercial: 0,
  };

  for (const c of data.customers) {
    counts[c.vehicleType] = (counts[c.vehicleType] || 0) + c.totalPaidWashes + c.totalFreeWashes;
  }

  return [
    { vehicleType: 'car' as VehicleType, label: 'Cars & SUVs', count: counts.car },
    { vehicleType: 'bike' as VehicleType, label: 'Motorcycles', count: counts.bike },
    { vehicleType: 'scooter' as VehicleType, label: 'Scooters', count: counts.scooter },
    { vehicleType: 'commercial' as VehicleType, label: 'All / Fleet', count: counts.commercial },
  ];
}

function computeMonthlyTrend(data: StoreData) {
  const now = new Date();
  const months: Array<{ key: string; month: string; paid: number; free: number }> = [];

  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    const label = d.toLocaleDateString('en-IN', { month: 'short' });
    months.push({ key, month: label, paid: 0, free: 0 });
  }

  for (const ev of data.events) {
    const dt = new Date(ev.createdAt);
    const key = `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
    const bucket = months.find((m) => m.key === key);
    if (!bucket) continue;
    if (ev.type === 'paid_wash') bucket.paid += 1;
    if (ev.type === 'free_redeemed') bucket.free += 1;
  }

  return months.map(({ month, paid, free }) => ({ month, paid, free }));
}

function getBearerToken(req: express.Request): string | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice(7).trim();
}

function requireCustomer(req: express.Request, res: express.Response): CustomerRecord | null {
  const token = getBearerToken(req);
  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return null;
  }
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'customer') {
    res.status(401).json({ error: 'Invalid or expired customer session' });
    return null;
  }
  const customer = store.customers.find((c) => c.id === payload.customerId);
  if (!customer) {
    res.status(404).json({ error: 'Customer record not found' });
    return null;
  }
  return customer;
}

function requireOwner(req: express.Request, res: express.Response): boolean {
  const token = getBearerToken(req);
  if (!token) {
    res.status(401).json({ error: 'Owner authentication required' });
    return false;
  }
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'owner') {
    res.status(401).json({ error: 'Invalid or expired owner session' });
    return false;
  }
  return true;
}

async function dispatchSmsAndNotification(params: {
  customerId: string;
  customerName: string;
  customerPhone: string;
  channel: 'sms' | 'in_app' | 'sms_and_app';
  title: string;
  message: string;
}): Promise<NotificationRecord> {
  let provider: 'twilio' | 'gateway' = 'gateway';
  let deliveryStatus: 'sent' | 'delivered' = 'delivered';

  const sid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM_NUMBER;

  if ((params.channel === 'sms' || params.channel === 'sms_and_app') && sid && authToken && from) {
    try {
      const body = new URLSearchParams({
        To: `+91${params.customerPhone}`,
        From: from,
        Body: params.message,
      });
      const resp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${Buffer.from(`${sid}:${authToken}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
      });
      if (resp.ok) {
        provider = 'twilio';
        deliveryStatus = 'sent';
      }
    } catch {
      // Fallback to local gateway record if Twilio call fails
    }
  }

  const record: NotificationRecord = {
    id: `ntf_${crypto.randomUUID().slice(0, 8)}`,
    customerId: params.customerId,
    customerName: params.customerName,
    customerPhone: params.customerPhone,
    channel: params.channel,
    title: params.title,
    message: params.message,
    deliveryStatus,
    provider,
    read: false,
    createdAt: new Date().toISOString(),
  };

  store.notifications.unshift(record);
  if (store.notifications.length > 200) {
    store.notifications = store.notifications.slice(0, 200);
  }
  return record;
}

async function startServer() {
  const app = express();
  app.use(express.json());

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, smsProvider: isTwilioConfigured() ? 'twilio' : 'gateway' });
  });

  app.get('/api/shop', (_req, res) => {
    res.json({
      settings: store.settings,
      services: VEHICLE_SERVICES,
    });
  });

  // Customer OTP flow
  app.post('/api/auth/send-otp', async (req, res) => {
    const phone = normalizePhone(req.body?.phone || '');
    if (!isValidIndianPhone(phone)) {
      res.status(400).json({ error: 'Please enter a valid 10-digit mobile number starting with 6–9.' });
      return;
    }

    const code = String(crypto.randomInt(100000, 999999));
    otpStore.set(phone, {
      code,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    const existing = store.customers.find((c) => c.phone === phone);
    const smsRecord = await dispatchSmsAndNotification({
      customerId: existing?.id || `pending_${phone}`,
      customerName: existing?.name || `Member ${phone.slice(-4)}`,
      customerPhone: phone,
      channel: 'sms',
      title: 'OTP Verification SMS',
      message: `${store.settings.shopName}: Your loyalty card verification OTP is ${code}. Valid for 5 minutes.`,
    });
    saveStore(store);

    const twilioSent = smsRecord.provider === 'twilio';

    res.json({
      ok: true,
      phone,
      maskedPhone: `+91 ${phone.slice(0, 5)} ${phone.slice(5)}`,
      expiresInSeconds: 300,
      smsStatus: smsRecord.deliveryStatus,
      smsProvider: smsRecord.provider,
      ...(twilioSent ? {} : { gatewayCode: code }),
    });
  });

  app.post('/api/auth/verify-otp', (req, res) => {
    const phone = normalizePhone(req.body?.phone || '');
    const otp = String(req.body?.otp || '').trim();
    const preferredVehicle = (req.body?.vehicleType as VehicleType) || 'car';

    if (!isValidIndianPhone(phone)) {
      res.status(400).json({ error: 'Invalid mobile number.' });
      return;
    }

    const entry = otpStore.get(phone);
    if (!entry) {
      res.status(400).json({ error: 'No active OTP found. Please request a new OTP.' });
      return;
    }
    if (Date.now() > entry.expiresAt) {
      otpStore.delete(phone);
      res.status(400).json({ error: 'OTP expired. Please request a new one.' });
      return;
    }
    if (entry.code !== otp) {
      res.status(400).json({ error: 'Incorrect OTP code. Please check and try again.' });
      return;
    }

    otpStore.delete(phone);

    let customer = store.customers.find((c) => c.phone === phone);
    let isNewCustomer = false;

    if (!customer) {
      isNewCustomer = true;
      const nowIso = new Date().toISOString();
      customer = {
        id: `cust_${crypto.randomUUID().slice(0, 8)}`,
        name: `Member ${phone.slice(-4)}`,
        phone,
        vehicleType: ['car', 'bike', 'scooter', 'commercial'].includes(preferredVehicle)
          ? preferredVehicle
          : 'car',
        stamps: 0,
        freeWashesAvailable: 0,
        totalPaidWashes: 0,
        totalFreeWashes: 0,
        cardsCompleted: 0,
        status: 'active',
        joinedAt: nowIso,
        lastVisitAt: nowIso,
      };
      store.customers.unshift(customer);
      saveStore(store);
    }

    const token = signToken({
      role: 'customer',
      customerId: customer.id,
      phone: customer.phone,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
    });

    const events = store.events
      .filter((e) => e.customerId === customer!.id)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const notifications = store.notifications
      .filter((n) => n.customerId === customer!.id || n.customerPhone === customer!.phone)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json({
      token,
      isNewCustomer,
      customer,
      events,
      notifications,
      settings: store.settings,
    });
  });

  app.get('/api/customer/me', (req, res) => {
    const customer = requireCustomer(req, res);
    if (!customer) return;

    const events = store.events
      .filter((e) => e.customerId === customer.id)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const notifications = store.notifications
      .filter((n) => n.customerId === customer.id || n.customerPhone === customer.phone)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json({
      customer,
      events,
      notifications,
      settings: store.settings,
    });
  });

  app.post('/api/customer/notifications/read', (req, res) => {
    const customer = requireCustomer(req, res);
    if (!customer) return;

    for (const n of store.notifications) {
      if (n.customerId === customer.id || n.customerPhone === customer.phone) {
        n.read = true;
      }
    }
    saveStore(store);

    const notifications = store.notifications
      .filter((n) => n.customerId === customer.id || n.customerPhone === customer.phone)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json({ notifications });
  });

  app.put('/api/customer/me', (req, res) => {
    const customer = requireCustomer(req, res);
    if (!customer) return;

    const name = String(req.body?.name || '').trim().slice(0, 60);
    const vehicleType = req.body?.vehicleType as VehicleType;

    if (name.length >= 2) {
      customer.name = name;
    }
    if (['car', 'bike', 'scooter', 'commercial'].includes(vehicleType)) {
      customer.vehicleType = vehicleType;
    }

    for (const ev of store.events) {
      if (ev.customerId === customer.id) {
        ev.customerName = customer.name;
      }
    }

    saveStore(store);
    res.json({ customer });
  });

  app.post('/api/customer/new-card', (req, res) => {
    const customer = requireCustomer(req, res);
    if (!customer) return;

    if (customer.stamps < store.settings.stampsRequired && customer.stamps > 0) {
      res.status(400).json({
        error: `Complete all ${store.settings.stampsRequired} stamps before starting a new card.`,
      });
      return;
    }

    customer.stamps = 0;
    const ev: WashEvent = {
      id: `evt_${crypto.randomUUID().slice(0, 8)}`,
      customerId: customer.id,
      customerName: customer.name,
      customerPhone: customer.phone,
      type: 'new_card',
      vehicleType: customer.vehicleType,
      stampsAfter: 0,
      stampsRequired: store.settings.stampsRequired,
      createdAt: new Date().toISOString(),
      note: 'Fresh loyalty card activated',
    };
    store.events.unshift(ev);
    saveStore(store);

    const events = store.events
      .filter((e) => e.customerId === customer.id)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json({ customer, events });
  });

  // Owner auth & dashboard
  app.get('/api/owner/status', (_req, res) => {
    res.json({
      pinConfigured: Boolean(store.ownerPinHash),
      smsProvider: isTwilioConfigured() ? 'twilio' : 'gateway',
    });
  });

  app.post('/api/owner/setup-pin', (req, res) => {
    if (store.ownerPinHash) {
      res.status(409).json({ error: 'Owner PIN is already configured. Please log in.' });
      return;
    }

    const pin = String(req.body?.pin || '').trim();
    if (!/^\d{4,6}$/.test(pin)) {
      res.status(400).json({ error: 'PIN must be 4 to 6 digits.' });
      return;
    }

    store.ownerPinHash = hashPin(pin);
    saveStore(store);

    const token = signToken({
      role: 'owner',
      exp: Date.now() + 24 * 60 * 60 * 1000,
    });

    res.status(201).json({ token });
  });

  app.post('/api/owner/login', (req, res) => {
    if (!store.ownerPinHash) {
      res.status(400).json({ error: 'Owner PIN has not been set up yet.' });
      return;
    }

    const pin = String(req.body?.pin || '').trim();
    if (!pin || !verifyPinHash(pin, store.ownerPinHash)) {
      res.status(401).json({ error: 'Incorrect Owner PIN.' });
      return;
    }

    const token = signToken({
      role: 'owner',
      exp: Date.now() + 24 * 60 * 60 * 1000,
    });

    res.json({ token });
  });

  app.get('/api/owner/dashboard', (req, res) => {
    if (!requireOwner(req, res)) return;

    const sortedCustomers = [...store.customers].sort(
      (a, b) => new Date(b.lastVisitAt).getTime() - new Date(a.lastVisitAt).getTime(),
    );
    const sortedEvents = [...store.events].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
    const sortedNotifications = [...store.notifications].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );

    res.json({
      kpis: computeKpis(store),
      settings: store.settings,
      customers: sortedCustomers,
      recentActivity: sortedEvents.slice(0, 50),
      notifications: sortedNotifications.slice(0, 40),
      vehicleBreakdown: computeVehicleBreakdown(store),
      monthlyTrend: computeMonthlyTrend(store),
    });
  });

  app.get('/api/owner/customers/search', (req, res) => {
    if (!requireOwner(req, res)) return;

    const rawQuery = String(req.query.q || '').trim();
    if (!rawQuery) {
      res.json({ customers: store.customers });
      return;
    }

    const extracted = extractPhoneFromQrOrQuery(rawQuery).toLowerCase();
    const digitsOnly = extracted.replace(/\D/g, '');

    const matches = store.customers.filter((c) => {
      if (digitsOnly && c.phone.includes(digitsOnly)) return true;
      return c.name.toLowerCase().includes(extracted);
    });

    res.json({ customers: matches });
  });

  app.post('/api/owner/customers', (req, res) => {
    if (!requireOwner(req, res)) return;

    const phone = normalizePhone(req.body?.phone || '');
    const name = String(req.body?.name || '').trim().slice(0, 60);
    const vehicleType = (req.body?.vehicleType as VehicleType) || 'car';

    if (!isValidIndianPhone(phone)) {
      res.status(400).json({ error: 'Enter a valid 10-digit mobile number starting with 6–9.' });
      return;
    }

    const existing = store.customers.find((c) => c.phone === phone);
    if (existing) {
      res.status(409).json({ error: 'A customer with this mobile number already exists.', customer: existing });
      return;
    }

    const nowIso = new Date().toISOString();
    const customer: CustomerRecord = {
      id: `cust_${crypto.randomUUID().slice(0, 8)}`,
      name: name.length >= 2 ? name : `Member ${phone.slice(-4)}`,
      phone,
      vehicleType: ['car', 'bike', 'scooter', 'commercial'].includes(vehicleType) ? vehicleType : 'car',
      stamps: 0,
      freeWashesAvailable: 0,
      totalPaidWashes: 0,
      totalFreeWashes: 0,
      cardsCompleted: 0,
      status: 'active',
      joinedAt: nowIso,
      lastVisitAt: nowIso,
    };

    store.customers.unshift(customer);
    saveStore(store);

    res.status(201).json({ customer });
  });

  app.post('/api/owner/stamp', async (req, res) => {
    if (!requireOwner(req, res)) return;

    const customerId = String(req.body?.customerId || '');
    const vehicleType = req.body?.vehicleType as VehicleType | undefined;
    const note = String(req.body?.note || '').trim().slice(0, 120);

    const customer = store.customers.find((c) => c.id === customerId);
    if (!customer) {
      res.status(404).json({ error: 'Customer not found.' });
      return;
    }

    const required = store.settings.stampsRequired;
    const usedVehicle: VehicleType =
      vehicleType && ['car', 'bike', 'scooter', 'commercial'].includes(vehicleType)
        ? vehicleType
        : customer.vehicleType;

    const startingStamps = customer.stamps >= required ? 0 : customer.stamps;
    const nextStamps = startingStamps + 1;
    const nowIso = new Date().toISOString();

    customer.stamps = nextStamps;
    customer.totalPaidWashes += 1;
    customer.lastVisitAt = nowIso;

    const paidEvent: WashEvent = {
      id: `evt_${crypto.randomUUID().slice(0, 8)}`,
      customerId: customer.id,
      customerName: customer.name,
      customerPhone: customer.phone,
      type: 'paid_wash',
      vehicleType: usedVehicle,
      stampsAfter: nextStamps,
      stampsRequired: required,
      createdAt: nowIso,
      note: note || `${usedVehicle.charAt(0).toUpperCase() + usedVehicle.slice(1)} paid wash`,
    };
    store.events.unshift(paidEvent);

    let earnedFreeWash = false;
    if (nextStamps >= required) {
      earnedFreeWash = true;
      customer.freeWashesAvailable += 1;
      customer.cardsCompleted += 1;

      const earnedEvent: WashEvent = {
        id: `evt_${crypto.randomUUID().slice(0, 8)}`,
        customerId: customer.id,
        customerName: customer.name,
        customerPhone: customer.phone,
        type: 'free_earned',
        vehicleType: usedVehicle,
        stampsAfter: nextStamps,
        stampsRequired: required,
        createdAt: new Date(Date.now() + 100).toISOString(),
        note: `Completed ${required} paid washes — 1 Free Wash unlocked`,
      };
      store.events.unshift(earnedEvent);
    }

    const remaining = Math.max(0, required - nextStamps);
    const notification = await dispatchSmsAndNotification({
      customerId: customer.id,
      customerName: customer.name,
      customerPhone: customer.phone,
      channel: 'sms_and_app',
      title: earnedFreeWash ? 'Free Wash Unlocked!' : `Stamp ${nextStamps}/${required} Added`,
      message: earnedFreeWash
        ? `${store.settings.shopName}: Congratulations ${customer.name}! You completed ${required}/${required} paid washes and unlocked 1 FREE wash!`
        : `${store.settings.shopName}: Stamp ${nextStamps}/${required} added for your ${usedVehicle} wash. Only ${remaining} more paid wash${remaining === 1 ? '' : 'es'} for a Free Wash!`,
    });

    saveStore(store);

    res.json({
      customer,
      earnedFreeWash,
      notification,
      kpis: computeKpis(store),
    });
  });

  app.post('/api/owner/redeem', async (req, res) => {
    if (!requireOwner(req, res)) return;

    const customerId = String(req.body?.customerId || '');
    const vehicleType = req.body?.vehicleType as VehicleType | undefined;
    const note = String(req.body?.note || '').trim().slice(0, 120);

    const customer = store.customers.find((c) => c.id === customerId);
    if (!customer) {
      res.status(404).json({ error: 'Customer not found.' });
      return;
    }

    const required = store.settings.stampsRequired;
    const hasReward = customer.freeWashesAvailable > 0 || customer.stamps >= required;
    if (!hasReward) {
      res.status(400).json({ error: 'This customer does not have an unlocked Free Wash yet.' });
      return;
    }

    const usedVehicle: VehicleType =
      vehicleType && ['car', 'bike', 'scooter', 'commercial'].includes(vehicleType)
        ? vehicleType
        : customer.vehicleType;

    if (customer.freeWashesAvailable > 0) {
      customer.freeWashesAvailable -= 1;
    }
    if (customer.stamps >= required) {
      customer.stamps = 0;
    }
    customer.totalFreeWashes += 1;
    customer.lastVisitAt = new Date().toISOString();

    const redeemEvent: WashEvent = {
      id: `evt_${crypto.randomUUID().slice(0, 8)}`,
      customerId: customer.id,
      customerName: customer.name,
      customerPhone: customer.phone,
      type: 'free_redeemed',
      vehicleType: usedVehicle,
      stampsAfter: customer.stamps,
      stampsRequired: required,
      createdAt: customer.lastVisitAt,
      note: note || 'Free loyalty wash redeemed',
    };
    store.events.unshift(redeemEvent);

    const notification = await dispatchSmsAndNotification({
      customerId: customer.id,
      customerName: customer.name,
      customerPhone: customer.phone,
      channel: 'sms_and_app',
      title: 'Free Wash Redeemed',
      message: `${store.settings.shopName}: Your FREE ${usedVehicle} wash has been redeemed! Thank you for choosing us — Happy Journey!`,
    });

    saveStore(store);

    res.json({
      customer,
      notification,
      kpis: computeKpis(store),
    });
  });

  app.post('/api/owner/notify', async (req, res) => {
    if (!requireOwner(req, res)) return;

    const customerId = String(req.body?.customerId || '');
    const channel = (req.body?.channel as 'sms' | 'in_app' | 'sms_and_app') || 'sms_and_app';
    const title = String(req.body?.title || 'Loyalty Update').trim().slice(0, 60);
    const message = String(req.body?.message || '').trim().slice(0, 280);

    const customer = store.customers.find((c) => c.id === customerId);
    if (!customer) {
      res.status(404).json({ error: 'Customer not found.' });
      return;
    }
    if (message.length < 4) {
      res.status(400).json({ error: 'Please enter a notification message (at least 4 characters).' });
      return;
    }

    const validChannel = ['sms', 'in_app', 'sms_and_app'].includes(channel)
      ? channel
      : 'sms_and_app';

    const notification = await dispatchSmsAndNotification({
      customerId: customer.id,
      customerName: customer.name,
      customerPhone: customer.phone,
      channel: validChannel,
      title: title || 'Loyalty Update',
      message,
    });

    saveStore(store);
    res.status(201).json({ notification });
  });

  app.put('/api/owner/settings', (req, res) => {
    if (!requireOwner(req, res)) return;

    const shopName = String(req.body?.shopName || '').trim().slice(0, 80);
    const tagline = String(req.body?.tagline || '').trim().slice(0, 100);
    const address = String(req.body?.address || '').trim().slice(0, 160);
    const supportPhone = String(req.body?.supportPhone || '').trim().slice(0, 20);
    const stampsRequired = Number(req.body?.stampsRequired);
    const newPin = String(req.body?.newPin || '').trim();

    if (shopName.length >= 2) store.settings.shopName = shopName;
    if (tagline.length >= 2) store.settings.tagline = tagline;
    if (address.length >= 5) store.settings.address = address;
    if (supportPhone.length >= 8) store.settings.supportPhone = supportPhone;
    if (Number.isInteger(stampsRequired) && stampsRequired >= 5 && stampsRequired <= 20) {
      store.settings.stampsRequired = stampsRequired;
    }
    if (newPin) {
      if (!/^\d{4,6}$/.test(newPin)) {
        res.status(400).json({ error: 'Owner PIN must be 4 to 6 digits.' });
        return;
      }
      store.ownerPinHash = hashPin(newPin);
    }

    saveStore(store);
    res.json({ settings: store.settings });
  });

  app.get('/shree-gurudatt-washing-center-github.zip', (_req, res) => {
    const zipPath = '/tmp/shree-gurudatt-washing-center-github.zip';
    try {
      const pyScript = `
import os, zipfile
root = os.getcwd()
out = ${JSON.stringify(zipPath)}
exclude_dirs = {'node_modules', 'dist', 'data', '.git', '.aistudio'}
exclude_files = {'bun.lock', '.DS_Store'}
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == '.':
            rel_dir = ''
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        if rel_dir.replace('\\\\', '/') == 'public/assets':
            dirnames[:] = [d for d in dirnames if d != 'aistudio']
        for fn in filenames:
            if fn in exclude_files or fn.endswith('.zip') or (fn.startswith('.env') and fn != '.env.example'):
                continue
            full_path = os.path.join(dirpath, fn)
            arc_name = os.path.join(rel_dir, fn) if rel_dir else fn
            zf.write(full_path, arc_name)
`;
      execFileSync('python3', ['-c', pyScript], { cwd: __dirname });
      res.download(zipPath, 'shree-gurudatt-washing-center-github.zip');
    } catch (err) {
      console.error('Failed to build GitHub source zip:', err);
      res.status(500).json({ error: 'Unable to package source archive.' });
    }
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Shree Gurudatt Loyalty server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
