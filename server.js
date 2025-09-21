import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mysql from 'mysql2/promise';

dotenv.config();
const app = express();
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// DB pool
const pool = await mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 4,
});

// Inbox em memória (demo). Para produção, persistir no DB.
const inbox = [];

// Helpers
function sign(user){ return jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' }); }
function auth(req,res,next){
  const h = req.headers.authorization||''; const token = h.startsWith('Bearer ')? h.slice(7) : null;
  if(!token) return res.status(401).json({error:'no token'});
  try{ req.user = jwt.verify(token, process.env.JWT_SECRET); return next(); }
  catch(e){ return res.status(401).json({error:'invalid token'}); }
}

// Seed do primeiro admin (uma vez)
app.post('/auth/seed-admin', async (req,res)=>{
  try{
    const { seed, name, email, password } = req.body||{};
    if(seed !== process.env.ADMIN_SEED) return res.status(403).json({error:'seed inválido'});
    const [rows] = await pool.query('SELECT id FROM agents WHERE email=?',[email]);
    if(rows.length) return res.status(400).json({error:'email já existe'});
    const hash = await bcrypt.hash(password, 10);
    const [r] = await pool.query('INSERT INTO agents (name,email,password_hash,role) VALUES (?,?,?,\"admin\")',[name,email,hash]);
    return res.json({ ok:true, id:r.insertId });
  }catch(e){ console.error(e); res.status(500).json({error:'fail'}); }
});

// Login
app.post('/auth/login', async (req,res)=>{
  const { email, password } = req.body||{};
  const [rows] = await pool.query('SELECT * FROM agents WHERE email=?',[email]);
  const u = rows[0];
  if(!u) return res.status(401).json({error:'credenciais inválidas'});
  const ok = await bcrypt.compare(password, u.password_hash);
  if(!ok) return res.status(401).json({error:'credenciais inválidas'});
  return res.json({ token: sign(u), user: { id:u.id, name:u.name, email:u.email, role:u.role } });
});

// Criar agente (admin)
app.post('/agents', auth, async (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({error:'forbidden'});
  const { name, email, password, role='agent' } = req.body||{};
  const hash = await bcrypt.hash(password, 10);
  try{
    const [r] = await pool.query('INSERT INTO agents (name,email,password_hash,role) VALUES (?,?,?,?)',[name,email,hash,role]);
    res.json({ id:r.insertId });
  }catch(e){ res.status(400).json({error:'email já existe'}); }
});

// Webhook verify
app.get('/webhook', (req,res)=>{
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if(mode==='subscribe' && token===VERIFY_TOKEN) return res.status(200).send(challenge);
  return res.sendStatus(403);
});

// Webhook receive
app.post('/webhook', (req,res)=>{
  try{
    const entry = req.body.entry?.[0];
    const changes = entry?.changes?.[0];
    const value = changes?.value; const msgs = value?.messages || [];
    msgs.forEach(m=>{
      const text = m.text?.body || m.button?.text || m.interactive?.list_reply?.title || '';
      const from = m.from; const name = value?.contacts?.[0]?.profile?.name || 'Contato'; const ts = Number(m.timestamp)*1000;
      inbox.push({ id:m.id, from, name, text, ts, direction:'in', status:'new' });
    });
  }catch(e){ console.error('Erro webhook:',e); }
  res.sendStatus(200);
});

// Listar mensagens (protegido)
app.get('/api/messages', auth, (req,res)=>{
  const data = [...inbox].sort((a,b)=>b.ts-a.ts).slice(0,500);
  res.json(data);
});

// Enviar mensagem (protegido)
app.post('/api/send', auth, async (req,res)=>{
  try{
    const { to, body } = req.body||{}; if(!to||!body) return res.status(400).json({error:'to e body são obrigatórios'});
    const url = `https://graph.facebook.com/v20.0/${process.env.PHONE_NUMBER_ID}/messages`;
    const r = await fetch(url, { method:'POST', headers:{ Authorization:`Bearer ${process.env.WHATSAPP_TOKEN}`, 'Content-Type':'application/json' }, body: JSON.stringify({ messaging_product:'whatsapp', to, type:'text', text:{ body } }) });
    const json = await r.json();
    inbox.push({ id: json.messages?.[0]?.id || Date.now().toString(), from: to, name: to, text: body, ts: Date.now(), direction:'out', status: r.ok?'sent':'error' });
    if(!r.ok) return res.status(400).json(json); return res.json(json);
  }catch(e){ console.error(e); res.status(500).json({error:'Falha ao enviar'}); }
});

// Arquivos estáticos
app.use(express.static(path.join(__dirname,'public')));

const port = process.env.PORT||3000;
app.listen(port, ()=>console.log(`OK em http://localhost:${port}`));
