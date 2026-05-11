
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'sd_invoice_v11_stable_secret';
const db = new Database('sd_invoice_v11_professional_invoice_format.db');

app.use(helmet({ contentSecurityPolicy:false }));
app.use(cors());
app.use(express.json({ limit:'30mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function addDays(days){ const d=new Date(); d.setDate(d.getDate()+days); return d.toISOString().slice(0,10); }
function today(){ return new Date().toISOString().slice(0,10); }
function hash(p){ return bcrypt.hashSync(p,10); }
function token(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn:'12h' }); }

db.exec(`
CREATE TABLE IF NOT EXISTS super_admins(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT UNIQUE,password_hash TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS plans(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 code TEXT UNIQUE,
 name TEXT,
 price REAL DEFAULT 0,
 duration_days INTEGER DEFAULT 30,
 max_branches INTEGER DEFAULT 1,
 max_users INTEGER DEFAULT 1,
 max_invoices INTEGER DEFAULT 100,
 gst INTEGER DEFAULT 1,
 tally_sap INTEGER DEFAULT 0,
 gsp INTEGER DEFAULT 0,
 white_label INTEGER DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 company_name TEXT,
 email TEXT UNIQUE,
 phone TEXT,
 gstin TEXT,
 address TEXT,
 plan TEXT DEFAULT 'trial',
 status TEXT DEFAULT 'Active',
 expiry_date TEXT,
 logo_data TEXT,
 logo_name TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS branches(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 master_id TEXT,
 branch_id TEXT,
 branch_name TEXT,
 branch_prefix TEXT,
 prefix TEXT,
 address TEXT,
 is_active INTEGER DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 branch_id INTEGER,
 user_id TEXT,
 password_hash TEXT,
 role TEXT,
 is_active INTEGER DEFAULT 1,
 UNIQUE(client_id,user_id)
);

CREATE TABLE IF NOT EXISTS customers(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 name TEXT,
 gstin TEXT,
 state TEXT,
 mobile TEXT,
 email TEXT,
 address TEXT,
 due_days INTEGER DEFAULT 15,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 name TEXT,
 hsn TEXT,
 price REAL DEFAULT 0,
 gst REAL DEFAULT 18,
 unit TEXT DEFAULT 'Nos',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rate_contracts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 customer_id INTEGER,
 product_id INTEGER,
 item_name TEXT,
 hsn TEXT,
 uom TEXT DEFAULT 'Nos',
 approved_rate REAL DEFAULT 0,
 gst REAL DEFAULT 18,
 discount REAL DEFAULT 0,
 start_date TEXT,
 end_date TEXT,
 status TEXT DEFAULT 'Active',
 manual_override INTEGER DEFAULT 0,
 remarks TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invoices(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 branch_id INTEGER,
 invoice_no TEXT,
 invoice_type TEXT,
 invoice_date TEXT,
 due_date TEXT,
 customer_name TEXT,
 total REAL DEFAULT 0,
 status TEXT DEFAULT 'Unpaid',
 invoice_json TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscription_invoices(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 invoice_no TEXT,
 plan_code TEXT,
 amount REAL DEFAULT 0,
 gst_amount REAL DEFAULT 0,
 total REAL DEFAULT 0,
 invoice_date TEXT,
 due_date TEXT,
 status TEXT,
 payment_mode TEXT,
 payment_ref TEXT,
 notes TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscription_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 plan_code TEXT,
 amount REAL DEFAULT 0,
 event_type TEXT,
 status TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS receipts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 branch_id INTEGER,
 invoice_no TEXT,
 customer_name TEXT,
 receipt_date TEXT,
 amount REAL DEFAULT 0,
 mode TEXT,
 ref_no TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credit_notes(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 branch_id INTEGER,
 credit_note_no TEXT,
 reference_invoice_id INTEGER,
 reference_invoice_no TEXT,
 credit_note_date TEXT,
 customer_name TEXT,
 reason TEXT,
 total REAL DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gst_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 report_type TEXT,
 period TEXT,
 status TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS integration_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 source_no TEXT,
 integration_type TEXT,
 status TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notification_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 channel TEXT,
 recipient TEXT,
 subject TEXT,
 message TEXT,
 status TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS white_label_settings(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER UNIQUE,
 brand_name TEXT,
 logo_url TEXT,
 primary_color TEXT,
 custom_domain TEXT,
 support_email TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 client_id INTEGER,
 login_type TEXT,
 user_id TEXT,
 action TEXT,
 details TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

function seed(){
  db.prepare("INSERT INTO super_admins(user_id,password_hash) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET password_hash=excluded.password_hash").run('superadmin', hash('admin123'));

  const planCount = db.prepare("SELECT COUNT(*) c FROM plans").get().c;
  if(planCount===0){
    const ins = db.prepare("INSERT INTO plans(code,name,price,duration_days,max_branches,max_users,max_invoices,gst,tally_sap,gsp,white_label) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
    ins.run('trial','Trial Yearly',0,365,5,5,100,1,0,0,0);
    ins.run('starter','Starter Yearly',2999,365,10,10,500,1,0,0,0);
    ins.run('business','Business Yearly',6999,365,25,25,5000,1,1,0,0);
    ins.run('premium','Premium Yearly',14999,365,999,999,999999,1,1,1,1);
    ins.run('yearly','Yearly Business',6999,365,999,999,999999,1,1,1,1);
  }

  let c = db.prepare("SELECT * FROM clients WHERE email=?").get('demo@sdinvoice.com');
  if(!c){
    const ci = db.prepare("INSERT INTO clients(company_name,email,phone,gstin,address,plan,status,expiry_date) VALUES(?,?,?,?,?,?,?,?)")
      .run('Demo Client Company','demo@sdinvoice.com','9999999999','24ABCDE1234F1Z5','Ahmedabad, Gujarat','premium','Active',addDays(365));
    const clientId = ci.lastInsertRowid;
    const br = db.prepare("INSERT INTO branches(client_id,master_id,branch_id,branch_name,branch_prefix,prefix,address,is_active) VALUES(?,?,?,?,?,?,?,1)")
      .run(clientId,'MASTER-001','BR-001','Main Branch','MAIN','MAIN','Ahmedabad');
    db.prepare("INSERT INTO users(client_id,branch_id,user_id,password_hash,role,is_active) VALUES(?,?,?,?,?,1)")
      .run(clientId,br.lastInsertRowid,'admin',hash('1234'),'ClientAdmin');
    db.prepare("INSERT INTO customers(client_id,name,gstin,state,mobile,email,address,due_days) VALUES(?,?,?,?,?,?,?,?)")
      .run(clientId,'ABC Traders','24ABCDE1234F1Z5','Gujarat','9999999999','abc@example.com','Ahmedabad',15);
    db.prepare("INSERT INTO products(client_id,name,hsn,price,gst,unit) VALUES(?,?,?,?,?,?)")
      .run(clientId,'Billing Software Setup','9983',5000,18,'Nos');
  }
}
seed();

try{db.prepare("ALTER TABLE clients ADD COLUMN subscription_start_date TEXT").run()}catch(e){}
try{db.prepare("ALTER TABLE clients ADD COLUMN subscription_end_date TEXT").run()}catch(e){}
try{db.prepare("ALTER TABLE subscription_invoices ADD COLUMN subscription_start_date TEXT").run()}catch(e){}
try{db.prepare("ALTER TABLE subscription_invoices ADD COLUMN subscription_end_date TEXT").run()}catch(e){}
try{db.prepare("UPDATE plans SET duration_days=365").run()}catch(e){}
try{db.prepare("UPDATE clients SET subscription_end_date=expiry_date WHERE (subscription_end_date IS NULL OR subscription_end_date='') AND expiry_date IS NOT NULL").run()}catch(e){}


function auth(req,res,next){
  try{
    const raw=(req.headers.authorization||'').replace('Bearer ','') || req.query.token || '';
    req.user=jwt.verify(raw,JWT_SECRET);
    next();
  }catch(e){ res.status(401).json({error:'Invalid token'}); }
}
function audit(req,action,details=''){
  try{ db.prepare("INSERT INTO audit_logs(client_id,login_type,user_id,action,details) VALUES(?,?,?,?,?)")
    .run(req.user?.clientId||null,req.user?.loginType||'',req.user?.userCode||req.user?.userId||'',action,typeof details==='string'?details:JSON.stringify(details)); }catch(e){}
}
function superOnly(req,res,next){ if(!req.user.superAdmin) return res.status(403).json({error:'Super Admin only'}); next(); }
function getDemoClientContext(){
  const client=db.prepare("SELECT * FROM clients WHERE email=?").get('demo@sdinvoice.com') || db.prepare("SELECT * FROM clients ORDER BY id LIMIT 1").get();
  if(!client) return null;
  const branch=db.prepare("SELECT * FROM branches WHERE client_id=? ORDER BY id LIMIT 1").get(client.id);
  return {client,branch};
}
function applySuperAdminClientContext(req){
  if(req.user && req.user.superAdmin){
    const ctx=getDemoClientContext();
    if(ctx){
      req.user.clientId=ctx.client.id;
      req.user.role='ClientAdmin';
      req.user.branchId=ctx.branch?ctx.branch.id:null;
      req.user.loginType='SuperAdminDemoClient';
      req.user.userCode='superadmin';
    }
  }
}
function clientOnly(req,res,next){ if(req.user.superAdmin){ applySuperAdminClientContext(req); } next(); }
function adminRole(req,res){ if(!['ClientAdmin','Accounts'].includes(req.user.role)){ res.status(403).json({error:'Permission denied'}); return false; } return true; }
function planRow(code){ return db.prepare("SELECT * FROM plans WHERE code=?").get(code) || db.prepare("SELECT * FROM plans WHERE code='trial'").get(); }
function usage(clientId){
  return {
    branches: db.prepare("SELECT COUNT(*) c FROM branches WHERE client_id=?").get(clientId).c,
    users: db.prepare("SELECT COUNT(*) c FROM users WHERE client_id=?").get(clientId).c,
    invoices: db.prepare("SELECT COUNT(*) c FROM invoices WHERE client_id=?").get(clientId).c
  };
}
function currentPlan(clientId){ const c=db.prepare("SELECT * FROM clients WHERE id=?").get(clientId); return planRow(c?.plan||'trial'); }
function checkLimit(clientId,type){
  const p=currentPlan(clientId), u=usage(clientId);
  if(type==='branch' && u.branches>=p.max_branches) return `Branch limit reached. Current plan allows ${p.max_branches} branches`;
  if(type==='user' && u.users>=p.max_users) return `User limit reached. Current plan allows ${p.max_users} users`;
  if(type==='invoice' && u.invoices>=p.max_invoices) return `Invoice limit reached. Current plan allows ${p.max_invoices} invoices`;
  return null;
}

app.get('/api/health',(req,res)=>res.json({version:'V11 Stable Full Release',status:'OK',super_admin:'superadmin / admin123',demo_client:'demo@sdinvoice.com / admin / 1234'}));
app.post('/api/repair-login',(req,res)=>{ seed(); res.json({success:true,message:'Login repaired',super_admin:'superadmin / admin123',demo_client:'demo@sdinvoice.com / admin / 1234'}); });

app.post('/api/super/login',async(req,res)=>{
  const userId=String(req.body.userId||req.body.user_id||'').trim();
  const password=String(req.body.password||'').trim();
  let s=db.prepare("SELECT * FROM super_admins WHERE user_id=?").get(userId);
  if(!s){ seed(); s=db.prepare("SELECT * FROM super_admins WHERE user_id=?").get(userId); }
  if(!s || !(await bcrypt.compare(password,s.password_hash))) return res.status(401).json({error:'Use superadmin / admin123'});
  res.json({success:true,token:token({superAdmin:true,loginType:'SuperAdmin',userCode:userId,userId}),user:{userId,role:'SuperAdmin'}});
});

app.post('/api/login',async(req,res)=>{
  const email=String(req.body.email||'').trim();
  const userId=String(req.body.userId||req.body.user_id||'').trim();
  const password=String(req.body.password||'').trim();
  const c=db.prepare("SELECT * FROM clients WHERE email=?").get(email);
  if(!c) return res.status(401).json({error:'Client email not found'});
  if(!['Active','Trial'].includes(c.status)) return res.status(403).json({error:'Client not active'});
  const u=db.prepare("SELECT * FROM users WHERE client_id=? AND user_id=? AND is_active=1").get(c.id,userId);
  if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Wrong client login'});
  res.json({success:true,token:token({loginType:'Client',clientId:c.id,userId:u.id,userCode:u.user_id,role:u.role,branchId:u.branch_id}),client:c,user:{userId:u.user_id,role:u.role,branchId:u.branch_id}});
});

app.get('/api/plans',(req,res)=>res.json(db.prepare("SELECT * FROM plans ORDER BY id").all()));
app.post('/api/super/plans',auth,superOnly,(req,res)=>{
  const d=req.body;
  try{
    db.prepare("INSERT INTO plans(code,name,price,duration_days,max_branches,max_users,max_invoices,gst,tally_sap,gsp,white_label) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
      .run(d.code,d.name,d.price||0,d.duration_days||30,d.max_branches||1,d.max_users||1,d.max_invoices||100,d.gst?1:0,d.tally_sap?1:0,d.gsp?1:0,d.white_label?1:0);
    res.json({success:true});
  }catch(e){ res.status(409).json({error:e.message}); }
});
app.put('/api/super/plans/:code',auth,superOnly,(req,res)=>{
  const d=req.body;
  db.prepare("UPDATE plans SET name=?,price=?,duration_days=?,max_branches=?,max_users=?,max_invoices=?,gst=?,tally_sap=?,gsp=?,white_label=? WHERE code=?")
    .run(d.name,d.price||0,d.duration_days||30,d.max_branches||1,d.max_users||1,d.max_invoices||100,d.gst?1:0,d.tally_sap?1:0,d.gsp?1:0,d.white_label?1:0,req.params.code);
  res.json({success:true});
});

app.get('/api/super/summary',auth,superOnly,(req,res)=>{
  const clients=db.prepare("SELECT * FROM clients").all();
  const mrr=clients.reduce((a,c)=>a+Number(planRow(c.plan).price||0),0);
  res.json({clients:clients.length,branches:db.prepare("SELECT COUNT(*) c FROM branches").get().c,users:db.prepare("SELECT COUNT(*) c FROM users").get().c,mrr});
});
app.get('/api/super/clients',auth,superOnly,(req,res)=>{
  res.json(db.prepare(`SELECT c.*,
  (SELECT COUNT(*) FROM branches b WHERE b.client_id=c.id) branches,
  (SELECT COUNT(*) FROM users u WHERE u.client_id=c.id) users,
  (SELECT COUNT(*) FROM invoices i WHERE i.client_id=c.id) invoices
  FROM clients c ORDER BY id DESC`).all());
});
app.post('/api/super/clients',auth,superOnly,async(req,res)=>{
  const d=req.body;
  if(!d.company_name || !d.email) return res.status(400).json({error:'Company name and email required'});
  try{
    const ci=db.prepare("INSERT INTO clients(company_name,email,phone,gstin,address,plan,status,expiry_date) VALUES(?,?,?,?,?,?,?,?)")
      .run(d.company_name,d.email,d.phone||'',d.gstin||'',d.address||'',d.plan||'trial',d.status||'Active',d.subscription_end_date||d.expiry_date||addDays(365));
    const clientId=ci.lastInsertRowid;
    const prefix=String(d.branch_prefix||d.prefix||'MAIN').toUpperCase();
    const br=db.prepare("INSERT INTO branches(client_id,master_id,branch_id,branch_name,branch_prefix,prefix,address,is_active) VALUES(?,?,?,?,?,?,?,1)")
      .run(clientId,d.master_id||'MASTER-001',d.branch_id||'BR-001',d.branch_name||'Main Branch',prefix,prefix,d.address||'');
    db.prepare("INSERT INTO users(client_id,branch_id,user_id,password_hash,role,is_active) VALUES(?,?,?,?,?,1)")
      .run(clientId,br.lastInsertRowid,d.user_id||'admin',await bcrypt.hash(d.password||'1234',10),'ClientAdmin');
    res.json({success:true,id:clientId,message:'Client created successfully'});
  }catch(e){ res.status(409).json({error:e.message}); }
});
app.put('/api/super/clients/:id',auth,superOnly,(req,res)=>{
  const d=req.body;
  db.prepare("UPDATE clients SET company_name=?,email=?,phone=?,gstin=?,address=?,plan=?,status=?,expiry_date=? WHERE id=?")
    .run(d.company_name,d.email,d.phone||'',d.gstin||'',d.address||'',d.plan||'trial',d.status||'Active',d.expiry_date||addDays(30),req.params.id);
  try{db.prepare("UPDATE clients SET subscription_start_date=?,subscription_end_date=?,expiry_date=? WHERE id=?").run(req.body.subscription_start_date||req.body.start_date||'',req.body.subscription_end_date||req.body.end_date||req.body.expiry_date||'',req.body.subscription_end_date||req.body.end_date||req.body.expiry_date||'',req.params.id)}catch(e){}
  res.json({success:true});
});
app.post('/api/super/clients/:id/status',auth,superOnly,(req,res)=>{
  db.prepare("UPDATE clients SET status=? WHERE id=?").run(req.body.status,req.params.id);
  res.json({success:true});
});

app.post('/api/super/offline-subscription',auth,superOnly,(req,res)=>{
  const d=req.body;
  const c=db.prepare("SELECT * FROM clients WHERE id=?").get(d.client_id);
  if(!c) return res.status(404).json({error:'Client not found'});
  const p=planRow(d.plan_code);
  const amount=Number(d.amount||p.price||0);
  const gst=amount*0.18;
  const total=amount+gst;
  const invNo='SUB-'+new Date().getFullYear()+'-'+String(db.prepare("SELECT COUNT(*) c FROM subscription_invoices").get().c+1).padStart(5,'0');
  const startDate=d.subscription_start_date||d.start_date||today();
  const endDate=d.subscription_end_date||d.end_date||addDays(365);
  if(!startDate || !endDate) return res.status(400).json({error:'Subscription start date and end date are required'});
  if(endDate < startDate) return res.status(400).json({error:'End date cannot be before start date'});
  db.prepare("UPDATE clients SET plan=?,status='Active',expiry_date=?,subscription_start_date=?,subscription_end_date=? WHERE id=?").run(p.code,endDate,startDate,endDate,d.client_id);
  db.prepare("INSERT INTO subscription_invoices(client_id,invoice_no,plan_code,amount,gst_amount,total,invoice_date,due_date,status,payment_mode,payment_ref,notes,subscription_start_date,subscription_end_date) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(d.client_id,invNo,p.code,amount,gst,total,today(),endDate,d.status||'Paid',d.payment_mode||'Offline',d.payment_ref||'',d.notes||'Yearly subscription',startDate,endDate);
  db.prepare("INSERT INTO subscription_events(client_id,plan_code,amount,event_type,status) VALUES(?,?,?,?,?)")
    .run(d.client_id,p.code,amount,'offline_subscription',d.status||'Paid');
  res.json({success:true,invoice_no:invNo,total});
});
app.get('/api/super/subscription-overview',auth,superOnly,(req,res)=>{
  const invoices=db.prepare("SELECT si.*,c.company_name,c.email,c.status client_status,c.expiry_date FROM subscription_invoices si LEFT JOIN clients c ON c.id=si.client_id ORDER BY si.id DESC").all();
  const events=db.prepare("SELECT se.*,c.company_name,c.email FROM subscription_events se LEFT JOIN clients c ON c.id=se.client_id ORDER BY se.id DESC").all();
  const clients=db.prepare("SELECT * FROM clients ORDER BY id DESC").all();
  res.json({clients,invoices,events,summary:{total_clients:clients.length,total_invoices:invoices.length,active:clients.filter(c=>c.status==='Active').length}});
});
app.get('/api/super/client/:id/subscription-summary',auth,superOnly,(req,res)=>{
  const client=db.prepare("SELECT * FROM clients WHERE id=?").get(req.params.id);
  if(!client) return res.status(404).json({error:'Client not found'});
  res.json({client,plan:planRow(client.plan),invoices:db.prepare("SELECT * FROM subscription_invoices WHERE client_id=? ORDER BY id DESC").all(client.id),events:db.prepare("SELECT * FROM subscription_events WHERE client_id=? ORDER BY id DESC").all(client.id)});
});

app.get('/api/me',auth,(req,res)=>{
  if(req.user.superAdmin){
    applySuperAdminClientContext(req);
    const c=db.prepare("SELECT * FROM clients WHERE id=?").get(req.user.clientId);
    return res.json({loginType:'SuperAdminDemoClient',client:c,user:req.user,plan:currentPlan(req.user.clientId),usage:usage(req.user.clientId)});
  }
  const c=db.prepare("SELECT * FROM clients WHERE id=?").get(req.user.clientId);
  res.json({loginType:'Client',client:c,user:req.user,plan:currentPlan(req.user.clientId),usage:usage(req.user.clientId)});
});
app.get('/api/company/profile',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM clients WHERE id=?").get(req.user.clientId)));
app.put('/api/company/logo',auth,clientOnly,(req,res)=>{
  db.prepare("UPDATE clients SET logo_data=?,logo_name=? WHERE id=?").run(req.body.logo_data||'',req.body.logo_name||'',req.user.clientId);
  res.json({success:true});
});

app.get('/api/subscription/invoices',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM subscription_invoices WHERE client_id=? ORDER BY id DESC").all(req.user.clientId)));
app.get('/api/subscription/events',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM subscription_events WHERE client_id=? ORDER BY id DESC").all(req.user.clientId)));

app.get('/api/branches',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM branches WHERE client_id=? ORDER BY id DESC").all(req.user.clientId)));
app.post('/api/branches',auth,clientOnly,(req,res)=>{
  if(!adminRole(req,res)) return;
  const d=req.body;
  const master=String(d.master_id||'').trim();
  const branchId=String(d.branch_id||'').trim();
  const name=String(d.branch_name||'').trim();
  const prefix=String(d.branch_prefix||d.prefix||'').trim().toUpperCase();
  if(!master||!branchId||!name||!prefix) return res.status(400).json({error:'Fill Master ID, Branch ID, Branch Name and Prefix'});
  const lim=checkLimit(req.user.clientId,'branch'); if(lim) return res.status(402).json({error:lim});
  const dup=db.prepare("SELECT id FROM branches WHERE client_id=? AND (LOWER(branch_id)=LOWER(?) OR LOWER(COALESCE(branch_prefix,''))=LOWER(?) OR LOWER(COALESCE(prefix,''))=LOWER(?))")
    .get(req.user.clientId,branchId,prefix,prefix);
  if(dup) return res.status(409).json({error:'Branch ID or Prefix already exists'});
  db.prepare("INSERT INTO branches(client_id,master_id,branch_id,branch_name,branch_prefix,prefix,address,is_active) VALUES(?,?,?,?,?,?,?,1)")
    .run(req.user.clientId,master,branchId,name,prefix,prefix,d.address||'');
  audit(req,'CREATE_BRANCH',{branchId,name,prefix});
  res.json({success:true,message:'Branch created successfully'});
});

app.get('/api/users',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT u.*,b.branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id WHERE u.client_id=? ORDER BY u.id DESC").all(req.user.clientId)));
app.post('/api/users',auth,clientOnly,async(req,res)=>{
  if(!adminRole(req,res)) return;
  const d=req.body; const lim=checkLimit(req.user.clientId,'user'); if(lim) return res.status(402).json({error:lim});
  db.prepare("INSERT INTO users(client_id,branch_id,user_id,password_hash,role,is_active) VALUES(?,?,?,?,?,1)")
    .run(req.user.clientId,d.branch_id,d.user_id,await bcrypt.hash(d.password||'1234',10),d.role||'Viewer');
  res.json({success:true});
});

app.get('/api/customers',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM customers WHERE client_id=? ORDER BY id DESC").all(req.user.clientId)));
app.post('/api/customers',auth,clientOnly,(req,res)=>{
  if(!adminRole(req,res)) return;
  const d=req.body;
  db.prepare("INSERT INTO customers(client_id,name,gstin,state,mobile,email,address,due_days) VALUES(?,?,?,?,?,?,?,?)")
    .run(req.user.clientId,d.name,d.gstin||'',d.state||'',d.mobile||'',d.email||'',d.address||'',d.due_days||15);
  res.json({success:true});
});
app.get('/api/products',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM products WHERE client_id=? ORDER BY id DESC").all(req.user.clientId)));
app.post('/api/products',auth,clientOnly,(req,res)=>{
  if(!adminRole(req,res)) return;
  const d=req.body;
  db.prepare("INSERT INTO products(client_id,name,hsn,price,gst,unit) VALUES(?,?,?,?,?,?)")
    .run(req.user.clientId,d.name,d.hsn||'',d.price||0,d.gst||18,d.unit||'Nos');
  res.json({success:true});
});

function nextNo(clientId,branchId,type){
  const b=db.prepare("SELECT * FROM branches WHERE id=? AND client_id=?").get(branchId,clientId);
  const prefix=b?.branch_prefix||b?.prefix||'MAIN';
  const code = type==='Proforma Invoice'?'PI':type==='Quotation'?'QT':'INV';
  const c=db.prepare("SELECT COUNT(*) c FROM invoices WHERE client_id=? AND branch_id=? AND invoice_type=?").get(clientId,branchId,type).c+1;
  return `${code}/${prefix}/${new Date().getFullYear()}/${String(c).padStart(4,'0')}`;
}
app.get('/api/next-invoice-no',auth,clientOnly,(req,res)=>res.json({invoice_no:nextNo(req.user.clientId,req.query.branch_id,req.query.type||'Tax Invoice')}));
app.get('/api/invoices',auth,clientOnly,(req,res)=>res.json(db.prepare("SELECT * FROM invoices WHERE client_id=? ORDER BY id DESC").all(req.user.clientId).map(i=>({...i,invoice_json:JSON.parse(i.invoice_json||'{}')}))));
app.post('/api/invoices',auth,clientOnly,(req,res)=>{
  const d=req.body;
  const lim=checkLimit(req.user.clientId,'invoice');
  if(lim) return res.status(402).json({error:lim});

  if(!d.invoice_no) return res.status(400).json({error:'Invoice number required'});
  if(!Array.isArray(d.items) || d.items.length===0) return res.status(400).json({error:'Please add at least one line item'});

  const duplicate=db.prepare("SELECT id FROM invoices WHERE client_id=? AND invoice_no=?").get(req.user.clientId,d.invoice_no);
  if(duplicate) return res.status(409).json({error:'Invoice number already exists. Please generate new invoice number.'});

  db.prepare("INSERT INTO invoices(client_id,branch_id,invoice_no,invoice_type,invoice_date,due_date,customer_name,total,status,invoice_json) VALUES(?,?,?,?,?,?,?,?,?,?)")
    .run(req.user.clientId,d.branch_id,d.invoice_no,d.invoice_type,d.invoice_date,d.due_date,d.customer_name,d.total||0,d.status||'Unpaid',JSON.stringify(d));
  res.json({success:true,message:'Invoice saved successfully'});
});


function invoiceHtml(inv){
  const client=db.prepare("SELECT * FROM clients WHERE id=?").get(inv.client_id)||{};
  const branch=db.prepare("SELECT * FROM branches WHERE id=?").get(inv.branch_id)||{};
  const data=JSON.parse(inv.invoice_json||'{}');
  const items=data.items||[];
  const subtotal=items.reduce((a,i)=>a+Number(i.taxable||0),0);
  const gstTotal=items.reduce((a,i)=>a+Number(i.gst_amount||0),0);
  const grand=Number(inv.total||0);
  const halfGst=gstTotal/2;
  const rupee=n=>'₹'+Number(n||0).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2});
  const logo=client.logo_data?`<img src="${client.logo_data}" class="company-logo">`:`<div class="logo-placeholder">${(client.company_name||'SD').substring(0,2).toUpperCase()}</div>`;
  const statusClass=(inv.status||'Unpaid').toLowerCase()==='paid'?'paid':((inv.status||'').toLowerCase()==='cancelled'?'cancelled':'pending');
  const rows=items.map((i,idx)=>`
    <tr>
      <td class="center">${idx+1}</td>
      <td><b>${i.name||''}</b></td>
      <td class="center">${i.hsn||''}</td>
      <td class="right">${Number(i.qty||0).toLocaleString('en-IN')}</td>
      <td class="right">${rupee(i.rate)}</td>
      <td class="right">${Number(i.gst||0)}%</td>
      <td class="right">${rupee(i.taxable)}</td>
      <td class="right">${rupee(i.gst_amount)}</td>
      <td class="right">${rupee(i.total)}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>${inv.invoice_no}</title>
<style>
*{box-sizing:border-box}
body{font-family:Arial,Helvetica,sans-serif;background:#eef2f7;margin:0;padding:24px;color:#111827}
.toolbar{max-width:1100px;margin:0 auto 14px;text-align:right}
button{background:#0f3157;color:#fff;border:0;border-radius:8px;padding:10px 16px;font-weight:700;cursor:pointer}
.invoice-wrapper{max-width:1100px;margin:auto;background:white;border-radius:14px;box-shadow:0 8px 28px rgba(15,49,87,.15);overflow:hidden}
.top-strip{height:9px;background:#0f3157}
.invoice-body{padding:30px}
.invoice-header{display:flex;justify-content:space-between;gap:20px;border-bottom:2px solid #0f3157;padding-bottom:20px}
.company-block{display:flex;gap:16px;width:58%}
.company-logo{width:90px;height:90px;object-fit:contain;border:1px solid #dbe3ef;border-radius:12px;padding:6px}
.logo-placeholder{width:90px;height:90px;border-radius:12px;background:#0f3157;color:white;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:800}
.company-details h1{margin:0 0 8px;color:#0f3157;font-size:28px}
.company-details p{margin:3px 0;font-size:13px;line-height:1.35}
.invoice-title{text-align:right;width:38%}
.invoice-title h2{margin:0 0 12px;color:#0f3157;font-size:30px;text-transform:uppercase}
.meta-table{width:100%;border-collapse:collapse;font-size:13px}
.meta-table td{border:1px solid #d6deeb;padding:8px}
.meta-table td:first-child{background:#f1f5fb;font-weight:700;width:45%}
.status-badge{display:inline-block;padding:6px 10px;border-radius:999px;font-size:12px;font-weight:800;text-transform:uppercase}
.paid{background:#dcfce7;color:#166534}.pending{background:#ffedd5;color:#9a3412}.cancelled{background:#fee2e2;color:#991b1b}
.billing-section{display:flex;gap:18px;margin-top:22px}
.bill-box,.branch-box{width:50%;border:1px solid #d6deeb;border-radius:12px;background:#f8fafc;padding:14px}
.bill-box h3,.branch-box h3{margin:0 0 10px;color:#0f3157;font-size:16px}
.bill-box p,.branch-box p{margin:4px 0;font-size:13px}
.invoice-table{width:100%;border-collapse:collapse;margin-top:24px;font-size:13px}
.invoice-table th{background:#0f3157;color:#fff;padding:10px;border:1px solid #0f3157}
.invoice-table td{border:1px solid #d6deeb;padding:9px;vertical-align:top}
.invoice-table tr:nth-child(even) td{background:#f9fbfd}
.center{text-align:center}.right{text-align:right}
.summary-row{display:flex;justify-content:space-between;gap:18px;margin-top:22px}
.amount-words{width:58%;border:1px solid #d6deeb;border-radius:12px;padding:14px;background:#f8fafc;font-size:13px}
.summary-table{width:38%;border-collapse:collapse;font-size:14px}
.summary-table td{border:1px solid #d6deeb;padding:10px}
.summary-table td:first-child{font-weight:700;background:#f8fafc}
.grand-total td{background:#0f3157!important;color:#fff;font-weight:800;font-size:16px}
.footer-section{display:flex;gap:18px;margin-top:28px}
.bank-details,.signature-box{width:50%;border:1px solid #d6deeb;border-radius:12px;padding:14px;min-height:130px}
.bank-details h3,.signature-box h3{margin:0 0 10px;color:#0f3157;font-size:15px}
.signature-box{text-align:center}.sign-space{height:54px}
.terms{margin-top:22px;border-top:1px solid #d6deeb;padding-top:14px;font-size:12px;color:#475569}
.watermark{position:fixed;top:45%;left:50%;transform:translate(-50%,-50%) rotate(-25deg);font-size:86px;font-weight:900;color:rgba(185,28,28,.08);pointer-events:none}
@media print{body{background:white;padding:0}.toolbar{display:none}.invoice-wrapper{box-shadow:none;border-radius:0}.top-strip,.invoice-table th,.grand-total td{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
</style>
</head>
<body>
<div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
${(inv.status||'').toLowerCase()==='cancelled'?'<div class="watermark">CANCELLED</div>':''}
<div class="invoice-wrapper"><div class="top-strip"></div><div class="invoice-body">
<div class="invoice-header">
  <div class="company-block">${logo}<div class="company-details">
    <h1>${client.company_name||'Company Name'}</h1>
    <p><b>GSTIN:</b> ${client.gstin||'-'}</p>
    <p><b>Address:</b> ${client.address||'-'}</p>
    <p><b>Email:</b> ${client.email||'-'}</p>
    <p><b>Phone:</b> ${client.phone||'-'}</p>
  </div></div>
  <div class="invoice-title"><h2>${inv.invoice_type||'Tax Invoice'}</h2>
    <table class="meta-table">
      <tr><td>Invoice No</td><td>${inv.invoice_no}</td></tr>
      <tr><td>Invoice Date</td><td>${inv.invoice_date||''}</td></tr>
      <tr><td>Due Date</td><td>${inv.due_date||''}</td></tr>
      <tr><td>Status</td><td><span class="status-badge ${statusClass}">${inv.status||'Unpaid'}</span></td></tr>
    </table>
  </div>
</div>
<div class="billing-section">
  <div class="bill-box"><h3>Bill To</h3><p><b>${inv.customer_name||''}</b></p><p>Customer details can be maintained in Customer Master.</p></div>
  <div class="branch-box"><h3>Branch / Outlet</h3><p><b>${branch.branch_name||''}</b></p><p><b>Branch ID:</b> ${branch.branch_id||''}</p><p><b>Prefix:</b> ${branch.branch_prefix||branch.prefix||''}</p></div>
</div>
<table class="invoice-table"><thead><tr><th>#</th><th>Description</th><th>HSN/SAC</th><th>Qty</th><th>Rate</th><th>GST</th><th>Taxable</th><th>GST Amt</th><th>Total</th></tr></thead><tbody>${rows}</tbody></table>
<div class="summary-row">
  <div class="amount-words"><b>Amount Summary</b><br>Taxable Value: ${rupee(subtotal)}<br>GST Total: ${rupee(gstTotal)}<br>Grand Total: ${rupee(grand)}</div>
  <table class="summary-table">
    <tr><td>Taxable Amount</td><td class="right">${rupee(subtotal)}</td></tr>
    <tr><td>CGST</td><td class="right">${rupee(halfGst)}</td></tr>
    <tr><td>SGST</td><td class="right">${rupee(halfGst)}</td></tr>
    <tr><td>Total GST</td><td class="right">${rupee(gstTotal)}</td></tr>
    <tr class="grand-total"><td>Grand Total</td><td class="right">${rupee(grand)}</td></tr>
  </table>
</div>
<div class="footer-section">
  <div class="bank-details"><h3>Bank Details</h3><p><b>Bank:</b> Please update bank details</p><p><b>Account No:</b> -</p><p><b>IFSC:</b> -</p><p><b>Payment Terms:</b> As per agreement</p></div>
  <div class="signature-box"><h3>For ${client.company_name||'Company'}</h3><div class="sign-space"></div><p><b>Authorised Signatory</b></p></div>
</div>
<div class="terms"><b>Terms & Conditions:</b><ol><li>Payment should be made as per agreed payment terms.</li><li>This is a system generated invoice.</li><li>Subject to applicable GST rules and reconciliation.</li></ol></div>
</div></div>
</body></html>`;
}

app.get('/api/invoice/:id/html',auth,(req,res)=>{
  const inv=db.prepare("SELECT * FROM invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
  if(!inv) return res.status(404).send('Invoice not found');
  res.send(invoiceHtml(inv));
});
app.get('/api/invoice/:id/download',auth,(req,res)=>{
  const inv=db.prepare("SELECT * FROM invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
  if(!inv) return res.status(404).send('Invoice not found');
  res.setHeader('Content-Disposition',`attachment; filename="${inv.invoice_no}.html"`);
  res.send(invoiceHtml(inv));
});

function subHtml(row){
  const c=db.prepare("SELECT * FROM clients WHERE id=?").get(row.client_id)||{};
  const logo=c.logo_data?`<img src="${c.logo_data}" style="max-height:70px;max-width:180px">`:'<h2>SD Invoice</h2>';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${row.invoice_no}</title><style>body{font-family:Arial;padding:30px}table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccc;padding:8px}th{background:#eef}@media print{button{display:none}}</style></head><body><button onclick="window.print()">Print / Save PDF</button>${logo}<h1>Subscription Invoice</h1><p><b>No:</b> ${row.invoice_no}<br><b>Date:</b> ${row.invoice_date}<br><b>Status:</b> ${row.status}</p><p><b>Bill To:</b> ${c.company_name}<br>${c.email}</p><table><tr><th>Plan</th><th>Amount</th><th>GST</th><th>Total</th></tr><tr><td>${row.plan_code}</td><td>₹${Number(row.amount||0).toFixed(2)}</td><td>₹${Number(row.gst_amount||0).toFixed(2)}</td><td>₹${Number(row.total||0).toFixed(2)}</td></tr></table></body></html>`;
}
app.get('/api/subscription-invoice/:id/html',auth,(req,res)=>{
  const row=req.user.superAdmin?db.prepare("SELECT * FROM subscription_invoices WHERE id=?").get(req.params.id):db.prepare("SELECT * FROM subscription_invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
  if(!row) return res.status(404).send('Subscription invoice not found');
  res.send(subHtml(row));
});
app.get('/api/subscription-invoice/:id/download',auth,(req,res)=>{
  const row=req.user.superAdmin?db.prepare("SELECT * FROM subscription_invoices WHERE id=?").get(req.params.id):db.prepare("SELECT * FROM subscription_invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
  if(!row) return res.status(404).send('Subscription invoice not found');
  res.setHeader('Content-Disposition',`attachment; filename="${row.invoice_no}.html"`);
  res.send(subHtml(row));
});


// STABLE FULL RELEASE MODULES

function rocStatus(r){
 const t=today();
 if(r.status!=='Active') return r.status;
 if(r.end_date && r.end_date < t) return 'Expired';
 if(r.start_date && r.start_date > t) return 'Upcoming';
 return 'Active';
}

app.get('/api/rate-contracts',auth,clientOnly,(req,res)=>{
 const rows=db.prepare(`SELECT rc.*,c.name customer_name,p.name product_name
 FROM rate_contracts rc
 LEFT JOIN customers c ON c.id=rc.customer_id
 LEFT JOIN products p ON p.id=rc.product_id
 WHERE rc.client_id=?
 ORDER BY rc.id DESC`).all(req.user.clientId).map(r=>({...r,computed_status:rocStatus(r)}));
 res.json(rows);
});
app.get('/api/rate-contracts/customer/:customerId',auth,clientOnly,(req,res)=>{
 const rows=db.prepare(`SELECT rc.*,c.name customer_name,p.name product_name
 FROM rate_contracts rc
 LEFT JOIN customers c ON c.id=rc.customer_id
 LEFT JOIN products p ON p.id=rc.product_id
 WHERE rc.client_id=? AND rc.customer_id=?
 ORDER BY rc.item_name`).all(req.user.clientId,req.params.customerId).map(r=>({...r,computed_status:rocStatus(r)}));
 res.json(rows);
});
app.post('/api/rate-contracts',auth,clientOnly,(req,res)=>{
 if(!adminRole(req,res)) return;
 const d=req.body;
 const cust=db.prepare("SELECT * FROM customers WHERE id=? AND client_id=?").get(d.customer_id,req.user.clientId);
 if(!cust) return res.status(404).json({error:'Customer/Vendor not found'});
 const prod=d.product_id?db.prepare("SELECT * FROM products WHERE id=? AND client_id=?").get(d.product_id,req.user.clientId):null;
 db.prepare(`INSERT INTO rate_contracts(client_id,customer_id,product_id,item_name,hsn,uom,approved_rate,gst,discount,start_date,end_date,status,manual_override,remarks)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
 .run(req.user.clientId,d.customer_id,d.product_id||null,d.item_name||(prod?prod.name:''),d.hsn||(prod?prod.hsn:''),d.uom||(prod?prod.unit:'Nos'),d.approved_rate||0,d.gst||(prod?prod.gst:18),d.discount||0,d.start_date||'',d.end_date||'',d.status||'Active',d.manual_override?1:0,d.remarks||'');
 res.json({success:true});
});
app.put('/api/rate-contracts/:id',auth,clientOnly,(req,res)=>{
 if(!adminRole(req,res)) return;
 const d=req.body;
 db.prepare(`UPDATE rate_contracts SET customer_id=?,product_id=?,item_name=?,hsn=?,uom=?,approved_rate=?,gst=?,discount=?,start_date=?,end_date=?,status=?,manual_override=?,remarks=? WHERE id=? AND client_id=?`)
 .run(d.customer_id,d.product_id||null,d.item_name||'',d.hsn||'',d.uom||'Nos',d.approved_rate||0,d.gst||18,d.discount||0,d.start_date||'',d.end_date||'',d.status||'Active',d.manual_override?1:0,d.remarks||'',req.params.id,req.user.clientId);
 res.json({success:true});
});
app.delete('/api/rate-contracts/:id',auth,clientOnly,(req,res)=>{
 if(!adminRole(req,res)) return;
 db.prepare("UPDATE rate_contracts SET status='Inactive' WHERE id=? AND client_id=?").run(req.params.id,req.user.clientId);
 res.json({success:true});
});
app.get('/api/reports/rate-contracts.csv',auth,clientOnly,(req,res)=>{
 const rows=db.prepare(`SELECT rc.*,c.name customer_name FROM rate_contracts rc LEFT JOIN customers c ON c.id=rc.customer_id WHERE rc.client_id=? ORDER BY c.name,rc.item_name`).all(req.user.clientId);
 const csv=['Customer,Item,HSN,UOM,Rate,GST,Discount,Start,End,Status,Manual Override',
 ...rows.map(r=>[r.customer_name,r.item_name,r.hsn,r.uom,r.approved_rate,r.gst,r.discount,r.start_date,r.end_date,rocStatus(r),r.manual_override?'Yes':'No'].map(v=>`"${String(v??'').replace(/"/g,'""')}"`).join(','))].join('\\n');
 res.setHeader('Content-Type','text/csv');
 res.setHeader('Content-Disposition','attachment; filename="Rate_Contract_Report.csv"');
 res.send(csv);
});

app.post('/api/receipts',auth,clientOnly,(req,res)=>{
 const d=req.body;
 db.prepare("INSERT INTO receipts(client_id,branch_id,invoice_no,customer_name,receipt_date,amount,mode,ref_no) VALUES(?,?,?,?,?,?,?,?)")
 .run(req.user.clientId,d.branch_id,d.invoice_no,d.customer_name,d.receipt_date||today(),d.amount||0,d.mode||'',d.ref_no||'');
 res.json({success:true});
});
app.get('/api/receipts',auth,clientOnly,(req,res)=>{
 res.json(db.prepare("SELECT * FROM receipts WHERE client_id=? ORDER BY id DESC").all(req.user.clientId));
});

app.post('/api/invoices/:id/cancel',auth,clientOnly,(req,res)=>{
 const inv=db.prepare("SELECT * FROM invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
 if(!inv)return res.status(404).json({error:'Invoice not found'});
 db.prepare("UPDATE invoices SET status='Cancelled' WHERE id=? AND client_id=?").run(req.params.id,req.user.clientId);
 res.json({success:true});
});
app.post('/api/invoices/:id/credit-note',auth,clientOnly,(req,res)=>{
 const inv=db.prepare("SELECT * FROM invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
 if(!inv)return res.status(404).json({error:'Invoice not found'});
 const cnt=db.prepare("SELECT COUNT(*) c FROM credit_notes WHERE client_id=?").get(req.user.clientId).c+1;
 const no='CN/'+new Date().getFullYear()+'/'+String(cnt).padStart(4,'0');
 db.prepare("INSERT INTO credit_notes(client_id,branch_id,credit_note_no,reference_invoice_id,reference_invoice_no,credit_note_date,customer_name,reason,total) VALUES(?,?,?,?,?,?,?,?,?)")
 .run(req.user.clientId,inv.branch_id,no,inv.id,inv.invoice_no,today(),inv.customer_name,req.body.reason||'Invoice cancelled',-Math.abs(inv.total||0));
 res.json({success:true,credit_note_no:no});
});
app.get('/api/credit-notes',auth,clientOnly,(req,res)=>{
 res.json(db.prepare("SELECT * FROM credit_notes WHERE client_id=? ORDER BY id DESC").all(req.user.clientId));
});

app.get('/api/reports/ledger',auth,clientOnly,(req,res)=>{
 const rows=[];
 db.prepare("SELECT * FROM invoices WHERE client_id=? ORDER BY invoice_date,id").all(req.user.clientId).forEach(i=>{
   const rec=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM receipts WHERE client_id=? AND invoice_no=?").get(req.user.clientId,i.invoice_no).s;
   rows.push({date:i.invoice_date,no:i.invoice_no,type:i.invoice_type,customer:i.customer_name,debit:i.total,credit:rec,balance:i.total-rec,status:i.status});
 });
 db.prepare("SELECT * FROM credit_notes WHERE client_id=? ORDER BY id").all(req.user.clientId).forEach(c=>{
   rows.push({date:c.credit_note_date,no:c.credit_note_no,type:'Credit Note',customer:c.customer_name,debit:0,credit:Math.abs(c.total),balance:c.total,status:'Approved'});
 });
 res.json(rows);
});

app.get('/api/gst/gstr1.json',auth,clientOnly,(req,res)=>{
 const invoices=db.prepare("SELECT * FROM invoices WHERE client_id=?").all(req.user.clientId);
 db.prepare("INSERT INTO gst_logs(client_id,report_type,period,status) VALUES(?,?,?,?)").run(req.user.clientId,'GSTR1_JSON',req.query.period||'', 'Generated');
 res.json({period:req.query.period||'',invoices});
});
app.get('/api/gst/logs',auth,clientOnly,(req,res)=>{
 res.json(db.prepare("SELECT * FROM gst_logs WHERE client_id=? ORDER BY id DESC").all(req.user.clientId));
});

app.get('/api/integrations/export/tally/:id',auth,clientOnly,(req,res)=>{
 const inv=db.prepare("SELECT * FROM invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
 if(!inv)return res.status(404).send('Not found');
 const xml=`<ENVELOPE><BODY><VOUCHER><VOUCHERNUMBER>${inv.invoice_no}</VOUCHERNUMBER><PARTYLEDGERNAME>${inv.customer_name}</PARTYLEDGERNAME><AMOUNT>${inv.total}</AMOUNT></VOUCHER></BODY></ENVELOPE>`;
 db.prepare("INSERT INTO integration_logs(client_id,source_no,integration_type,status) VALUES(?,?,?,?)").run(req.user.clientId,inv.invoice_no,'TALLY_XML','Exported');
 res.setHeader('Content-Type','application/xml');
 res.setHeader('Content-Disposition',`attachment; filename="${inv.invoice_no}_tally.xml"`);
 res.send(xml);
});
app.get('/api/integrations/export/sap/:id',auth,clientOnly,(req,res)=>{
 const inv=db.prepare("SELECT * FROM invoices WHERE id=? AND client_id=?").get(req.params.id,req.user.clientId);
 if(!inv)return res.status(404).json({error:'Not found'});
 db.prepare("INSERT INTO integration_logs(client_id,source_no,integration_type,status) VALUES(?,?,?,?)").run(req.user.clientId,inv.invoice_no,'SAP_JSON','Exported');
 res.json({DocType:'Invoice',NumAtCard:inv.invoice_no,CardName:inv.customer_name,DocTotal:inv.total});
});
app.get('/api/integrations/logs',auth,clientOnly,(req,res)=>{
 res.json(db.prepare("SELECT * FROM integration_logs WHERE client_id=? ORDER BY id DESC").all(req.user.clientId));
});

app.get('/api/ai/analytics',auth,clientOnly,(req,res)=>{
 const invoices=db.prepare("SELECT * FROM invoices WHERE client_id=?").all(req.user.clientId);
 const total=invoices.reduce((a,b)=>a+Number(b.total||0),0);
 const cancelled=invoices.filter(i=>i.status==='Cancelled').length;
 res.json({summary:{invoices:invoices.length,net_sales:total,cancelled},insights:[total>0?'Revenue activity started.':'No revenue yet.',cancelled>0?'Review cancelled invoices.':'No cancelled invoice detected.'],recommendations:['Track outstanding payment weekly.','Export GST summary monthly.']});
});

app.post('/api/notifications/send',auth,clientOnly,(req,res)=>{
 db.prepare("INSERT INTO notification_logs(client_id,channel,recipient,subject,message,status) VALUES(?,?,?,?,?,?)").run(req.user.clientId,req.body.channel,req.body.recipient,req.body.subject,req.body.message,'Demo Sent');
 res.json({success:true,message:'Notification logged as demo sent'});
});
app.get('/api/notifications/logs',auth,clientOnly,(req,res)=>{
 res.json(db.prepare("SELECT * FROM notification_logs WHERE client_id=? ORDER BY id DESC").all(req.user.clientId));
});

app.get('/api/white-label/settings',auth,clientOnly,(req,res)=>{
 db.prepare("INSERT OR IGNORE INTO white_label_settings(client_id,brand_name,primary_color) VALUES(?,?,?)").run(req.user.clientId,'SD Invoice','#0f3157');
 res.json(db.prepare("SELECT * FROM white_label_settings WHERE client_id=?").get(req.user.clientId));
});
app.put('/api/white-label/settings',auth,clientOnly,(req,res)=>{
 const d=req.body;
 db.prepare("INSERT OR REPLACE INTO white_label_settings(client_id,brand_name,logo_url,primary_color,custom_domain,support_email) VALUES(?,?,?,?,?,?)")
 .run(req.user.clientId,d.brand_name||'SD Invoice',d.logo_url||'',d.primary_color||'#0f3157',d.custom_domain||'',d.support_email||'');
 res.json({success:true});
});


app.get('/api/audit',auth,(req,res)=>res.json(db.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").all()));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log('SD Invoice V11 Stable Full Release - Professional Invoice Format running at http://localhost:'+PORT));
