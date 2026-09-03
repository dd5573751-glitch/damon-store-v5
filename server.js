const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA = path.join(__dirname, "data.json");
const DATA_SECRET = String(process.env.DATA_ENCRYPTION_KEY || "");
function dataKey(){ if(!/^[a-f0-9]{64}$/i.test(DATA_SECRET)) throw new Error("DATA_ENCRYPTION_KEY must be 64 hex characters"); return Buffer.from(DATA_SECRET,"hex"); }
function encryptData(text){
  const iv=crypto.randomBytes(12), c=crypto.createCipheriv("aes-256-gcm",dataKey(),iv);
  const data=Buffer.concat([c.update(text,"utf8"),c.final()]);
  return JSON.stringify({v:1,iv:iv.toString("base64"),tag:c.getAuthTag().toString("base64"),data:data.toString("base64")});
}
function decryptData(text){
  const x=JSON.parse(text), d=crypto.createDecipheriv("aes-256-gcm",dataKey(),Buffer.from(x.iv,"base64"));
  d.setAuthTag(Buffer.from(x.tag,"base64"));
  return Buffer.concat([d.update(Buffer.from(x.data,"base64")),d.final()]).toString("utf8");
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "64kb" }));
app.use(cookieParser());
const apiLimiter=rateLimit({windowMs:15*60*1000,limit:180,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Quá nhiều yêu cầu, thử lại sau."}});
const authLimiter=rateLimit({windowMs:10*60*1000,limit:20,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Quá nhiều lần đăng nhập/thử tài khoản. Thử lại sau."}});
const buyLimiter=rateLimit({windowMs:60*1000,limit:12,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Thao tác mua quá nhanh. Thử lại sau."}});
const adminLimiter=rateLimit({windowMs:60*1000,limit:60,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Quá nhiều yêu cầu quản trị."}});
app.use("/api",apiLimiter);

function now(){ return new Date().toISOString(); }
function monthKey(){ return new Date().toISOString().slice(0,7); }
function cleanUsername(v){ return String(v||"").trim().toLowerCase(); }
function validUsername(v){ return /^[a-zA-Z0-9_]{3,24}$/.test(String(v||"")); }
function hash(pw, salt=crypto.randomBytes(16).toString("hex")){
  return `${salt}:${crypto.scryptSync(String(pw), salt, 64).toString("hex")}`;
}
function verify(pw, stored){
  try{
    const [salt,key]=String(stored).split(":");
    const actual=crypto.scryptSync(String(pw),salt,64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(actual,"hex"),Buffer.from(key,"hex"));
  }catch{return false;}
}
function load(){
  if(!fs.existsSync(DATA)){
    const db={users:[],products:[],deposits:[],purchases:[],sessions:{},settings:{month:monthKey(),previousWinner:null}};
    fs.writeFileSync(DATA,encryptData(JSON.stringify(db,null,2)),{mode:0o600});
    return db;
  }
  return JSON.parse(decryptData(fs.readFileSync(DATA,"utf8")));
}
function save(db){
  const tmp=DATA+".tmp";
  fs.writeFileSync(tmp,encryptData(JSON.stringify(db,null,2)),{mode:0o600});
  fs.renameSync(tmp,DATA);
}
let db=load();

function ensureAdmin(){
  const username=cleanUsername(process.env.ADMIN_USERNAME);
  const password=String(process.env.ADMIN_PASSWORD||"");
  if(!validUsername(username)||password.length<8) return;
  let u=db.users.find(x=>x.username===username);
  if(!u){
    db.users.push({id:crypto.randomUUID(),username,passwordHash:hash(password),role:"admin",balance:0,sellerApproved:true,banned:false,createdAt:now(),totalDeposited:0});
    save(db);
  }
}
ensureAdmin();

function resetMonthIfNeeded(){
  const m=monthKey();
  if(db.settings.month!==m){
    const totals={};
    for(const d of db.deposits.filter(x=>x.status==="approved")){
      const dm=String(d.createdAt).slice(0,7);
      if(dm===db.settings.month) totals[d.username]=(totals[d.username]||0)+Number(d.amount||0);
    }
    const winner=Object.entries(totals).sort((a,b)=>b[1]-a[1])[0];
    db.settings.previousWinner=winner?{username:winner[0],amount:winner[1],month:db.settings.month}:null;
    db.settings.month=m; save(db);
  }
}
resetMonthIfNeeded();

function auth(req,res,next){
  resetMonthIfNeeded();
  const sid=req.cookies.damon_session;
  const username=sid&&db.sessions[sid];
  const u=username&&db.users.find(x=>x.username===username);
  if(!u||u.banned) return res.status(401).json({error:"Vui lòng đăng nhập"});
  req.user=u; next();
}
function admin(req,res,next){
  auth(req,res,()=>req.user.role==="admin"?next():res.status(403).json({error:"Chỉ Admin"}));
}
// Never expose key values from public API.
function publicProduct(p){
  return {id:p.id,name:p.name,price:p.price,description:p.description,active:p.active,keysAvailable:Array.isArray(p.keys)?p.keys.filter(k=>!k.sold).length:0};
}

app.get("/api/config",(req,res)=>res.json({
  bankName:process.env.BANK_NAME||"MB Bank",
  bankNumber:process.env.BANK_NUMBER||"",
  bankOwner:process.env.BANK_OWNER||"",
  supportPhone:process.env.SUPPORT_PHONE||""
}));

app.post("/api/register",authLimiter,(req,res)=>{
  const username=cleanUsername(req.body.username),pw=String(req.body.password||"");
  if(!validUsername(username)) return res.status(400).json({error:"Tên đăng nhập 3-24 ký tự, chỉ gồm chữ, số và _"});
  if(pw.length<8) return res.status(400).json({error:"Mật khẩu tối thiểu 8 ký tự"});
  if(db.users.some(x=>x.username===username)) return res.status(409).json({error:"Tên đăng nhập đã tồn tại"});
  db.users.push({id:crypto.randomUUID(),username,passwordHash:hash(pw),role:"user",balance:0,sellerApproved:false,banned:false,createdAt:now(),totalDeposited:0});
  save(db); loginUser(res,username); res.json({ok:true});
});
function loginUser(res,username){
  const sid=crypto.randomBytes(32).toString("hex");
  db.sessions[sid]=username; save(db);
  res.cookie("damon_session",sid,{httpOnly:true,sameSite:"lax",secure:process.env.COOKIE_SECURE==="true",maxAge:30*24*60*60*1000});
}
app.post("/api/login",authLimiter,(req,res)=>{
  const username=cleanUsername(req.body.username),pw=String(req.body.password||"");
  const u=db.users.find(x=>x.username===username);
  if(!u||u.banned||!verify(pw,u.passwordHash)) return res.status(401).json({error:"Tên đăng nhập hoặc mật khẩu không đúng"});
  loginUser(res,username); res.json({ok:true});
});
app.post("/api/logout",(req,res)=>{
  const sid=req.cookies.damon_session;if(sid) delete db.sessions[sid];save(db);
  res.clearCookie("damon_session");res.json({ok:true});
});
app.get("/api/me",(req,res)=>{
  resetMonthIfNeeded();
  const sid=req.cookies.damon_session,username=sid&&db.sessions[sid],u=username&&db.users.find(x=>x.username===username);
  if(!u||u.banned) return res.json({user:null});
  const winner=db.settings.previousWinner&&db.settings.previousWinner.username===u.username;
  res.json({user:{username:u.username,role:u.role,balance:u.balance,sellerApproved:u.sellerApproved,sellerRequested:!!u.sellerRequested,previousWinner:winner}});
});

app.get("/api/products",(req,res)=>res.json(db.products.filter(x=>x.active!==false).map(publicProduct)));

app.post("/api/deposits",auth,(req,res)=>{
  const amount=Number(req.body.amount);
  if(!Number.isFinite(amount)||amount<10000||amount>100000000) return res.status(400).json({error:"Số tiền không hợp lệ"});
  const d={id:crypto.randomUUID(),username:req.user.username,amount,content:`NAPTIEN ${req.user.username}`,status:"pending",createdAt:now()};
  db.deposits.push(d);save(db);res.json({ok:true,deposit:d});
});
app.get("/api/history/deposits",auth,(req,res)=>res.json(db.deposits.filter(x=>x.username===req.user.username).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));

app.post("/api/card-topup",auth,(req,res)=>{
  const serial=String(req.body.serial||"").trim();
  const code=String(req.body.code||"").trim();
  const telco=String(req.body.telco||"").trim();

  if(!serial || !code || !telco)
    return res.status(400).json({error:"Vui lòng nhập nhà mạng, số seri và mã thẻ"});

  if(serial.length<5 || code.length<6)
    return res.status(400).json({error:"Số seri hoặc mã thẻ không hợp lệ"});

  const card={
    id:crypto.randomUUID(),
    username:req.user.username,
    telco,
    serial,
    code,
    status:"pending",
    createdAt:new Date().toISOString()
  };

  if(!db.cardTopups) db.cardTopups=[];
  db.cardTopups.push(card);
  save(db);

  res.json({ok:true,message:"Đã gửi thẻ, vui lòng chờ Admin duyệt"});
});

app.get("/api/history/purchases",auth,(req,res)=>res.json(db.purchases.filter(x=>x.username===req.user.username).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));

app.get("/api/topup-ranking",(req,res)=>{
  resetMonthIfNeeded();const m=monthKey(),totals={};
  for(const d of db.deposits.filter(x=>x.status==="approved"&&String(x.createdAt).slice(0,7)===m))
    totals[d.username]=(totals[d.username]||0)+Number(d.amount||0);
  const rows=Object.entries(totals).map(([username,amount])=>({username,amount})).sort((a,b)=>b.amount-a.amount).slice(0,20);
  res.json({month:m,rows,previousWinner:db.settings.previousWinner});
});


app.post("/api/card-deposit",auth,(req,res)=>{
  const cardType=String(req.body.cardType||"").trim();
  const serial=String(req.body.serial||"").trim();
  const code=String(req.body.code||"").trim();
  const amount=Number(req.body.amount);

  if(!cardType || !serial || !code || !Number.isFinite(amount) || amount<1000 || amount>10000000)
    return res.status(400).json({error:"Thông tin thẻ không hợp lệ"});

  if(!db.deposits) db.deposits=[];

  const d={
    id:crypto.randomUUID(),
    username:req.user.username,
    amount,
    content:`CARD|${cardType}|SERIAL:${serial}|CODE:${code}`,
    cardType,
    serial,
    code,
    method:"card",
    status:"pending",
    createdAt:Date.now()
  };

  db.deposits.push(d);
  save(db);
  res.json({ok:true,deposit:d});
});

app.post("/api/buy/:id",buyLimiter,auth,(req,res)=>{
  const p=db.products.find(x=>x.id===req.params.id&&x.active!==false);
  if(!p)return res.status(404).json({error:"Không tìm thấy sản phẩm"});
  if(!Array.isArray(p.keys)||!p.keys.some(k=>!k.sold)) return res.status(400).json({error:"Sản phẩm đã hết KEY"});
  let discount=0;
  if(req.user.sellerApproved) discount=0.15;
  if(db.settings.previousWinner&&db.settings.previousWinner.username===req.user.username) discount=Math.max(discount,0.08);
  const price=Math.round(Number(p.price)*(1-discount));
  if(req.user.balance<price)return res.status(400).json({error:"Số dư không đủ"});
  const key=p.keys.find(k=>!k.sold);
  key.sold=true;key.soldTo=req.user.username;key.soldAt=now();
  req.user.balance-=price;
  const purchase={id:crypto.randomUUID(),username:req.user.username,productId:p.id,productName:p.name,price,discount,key:key.value,createdAt:now(),status:"success"};
  db.purchases.push(purchase);save(db);
  res.json({ok:true,purchase,balance:req.user.balance});
});
app.post("/api/apply-seller",auth,(req,res)=>{
  if(req.user.sellerApproved)return res.status(400).json({error:"Bạn đã là Seller"});
  req.user.sellerRequested=true;save(db);res.json({ok:true});
});

app.get("/api/admin/users",adminLimiter,admin,(req,res)=>res.json(db.users.map(u=>({username:u.username,role:u.role,balance:u.balance,sellerApproved:u.sellerApproved,sellerRequested:!!u.sellerRequested,banned:u.banned,createdAt:u.createdAt,totalDeposited:u.totalDeposited||0}))));
app.post("/api/admin/users/:username/ban",adminLimiter,admin,(req,res)=>{
  const u=db.users.find(x=>x.username===cleanUsername(req.params.username));if(!u)return res.status(404).json({error:"Không tìm thấy"});
  if(u.role==="admin")return res.status(400).json({error:"Không thể ban Admin"});
  u.banned=Boolean(req.body.banned);save(db);res.json({ok:true});
});
app.post("/api/admin/sellers/:username",adminLimiter,admin,(req,res)=>{
  const u=db.users.find(x=>x.username===cleanUsername(req.params.username));if(!u)return res.status(404).json({error:"Không tìm thấy"});
  u.sellerApproved=true;u.sellerRequested=false;save(db);res.json({ok:true});
});
app.get("/api/admin/deposits",adminLimiter,admin,(req,res)=>res.json(db.deposits.slice().sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.post("/api/admin/deposits/:id",adminLimiter,admin,(req,res)=>{
  const d=db.deposits.find(x=>x.id===req.params.id);if(!d)return res.status(404).json({error:"Không tìm thấy"});
  if(d.status!=="pending")return res.status(400).json({error:"Giao dịch đã xử lý"});
  const u=db.users.find(x=>x.username===d.username);if(!u)return res.status(404).json({error:"User không tồn tại"});
  if(req.body.status==="approved"){d.status="approved";u.balance+=d.amount;u.totalDeposited=(u.totalDeposited||0)+d.amount}
  else if(req.body.status==="rejected")d.status="rejected";else return res.status(400).json({error:"Trạng thái không hợp lệ"});
  save(db);res.json({ok:true});
});

app.get("/api/admin/products",adminLimiter,admin,(req,res)=>res.json(db.products));
app.post("/api/admin/products",adminLimiter,admin,(req,res)=>{
  const name=String(req.body.name||"").trim(),price=Number(req.body.price),description=String(req.body.description||"").trim();
  if(!name||!Number.isFinite(price)||price<=0)return res.status(400).json({error:"Dữ liệu sản phẩm không hợp lệ"});
  const p={id:crypto.randomUUID(),name,price,description,active:true,createdAt:now(),keys:[]};
  db.products.push(p);save(db);res.json(p);
});
app.delete("/api/admin/products/:id",adminLimiter,admin,(req,res)=>{
  const p=db.products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:"Không tìm thấy"});
  p.active=false;save(db);res.json({ok:true});
});
app.post("/api/admin/products/:id/keys",adminLimiter,admin,(req,res)=>{
  const p=db.products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:"Không tìm thấy"});
  const raw=Array.isArray(req.body.keys)?req.body.keys:[String(req.body.key||"")];
  const keys=raw.map(x=>String(x).trim()).filter(Boolean);
  if(!keys.length)return res.status(400).json({error:"Chưa nhập KEY"});
  if(!Array.isArray(p.keys))p.keys=[];
  const existing=new Set(p.keys.map(k=>k.value));
  for(const value of keys) if(!existing.has(value)){p.keys.push({id:crypto.randomUUID(),value,sold:false});existing.add(value)}
  save(db);res.json({ok:true,added:keys.filter(v=>existing.has(v)).length,product:p});
});
app.get("/api/admin/products/:id/keys",adminLimiter,admin,(req,res)=>{
  const p=db.products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:"Không tìm thấy"});
  res.json((p.keys||[]).map(k=>({id:k.id,sold:k.sold,soldTo:k.soldTo||null,soldAt:k.soldAt||null,value:k.sold?"[ĐÃ BÁN]":k.value})));
});
app.get("/api/admin/stats",adminLimiter,admin,(req,res)=>res.json({
  users:db.users.length,orders:db.purchases.length,revenue:db.purchases.reduce((s,x)=>s+x.price,0),
  balance:db.users.reduce((s,x)=>s+x.balance,0),pendingDeposits:db.deposits.filter(x=>x.status==="pending").length,
  products:db.products.filter(x=>x.active!==false).length,keys:db.products.reduce((s,p)=>s+(p.keys||[]).filter(k=>!k.sold).length,0)
}));

app.use(express.static(path.join(__dirname,"public")));
app.get("/{*splat}",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));


// ================= CARD TOPUP ADMIN =================

app.get("/api/admin/card-topups", auth, (req, res) => {
  if (!req.user || req.user.role !== "admin")
    return res.status(403).json({error:"Admin only"});

  if (!db.cardTopups) db.cardTopups = [];

  // Chỉ Admin mới nhận được serial + code
  res.json({
    ok: true,
    items: db.cardTopups
      .slice()
      .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))
  });
});

app.post("/api/admin/card-topups/:id/approve", auth, (req, res) => {
  if (!req.user || req.user.role !== "admin")
    return res.status(403).json({error:"Admin only"});

  if (!db.cardTopups) db.cardTopups = [];

  const card = db.cardTopups.find(x => x.id === req.params.id);

  if (!card)
    return res.status(404).json({error:"Không tìm thấy đơn thẻ"});

  if (card.status !== "pending")
    return res.status(400).json({error:"Đơn này đã được xử lý"});

  const user = db.users?.find
    ? db.users.find(u => u.username === card.username)
    : null;

  if (!user)
    return res.status(404).json({error:"Không tìm thấy user"});

  user.balance = Number(user.balance || 0) + Number(card.amount || 0);

  card.status = "approved";
  card.approvedAt = new Date().toISOString();
  card.approvedBy = req.user.username;

  save(db);

  res.json({
    ok:true,
    message:"Đã duyệt thẻ và cộng tiền cho user"
  });
});

app.post("/api/admin/card-topups/:id/reject", auth, (req, res) => {
  if (!req.user || req.user.role !== "admin")
    return res.status(403).json({error:"Admin only"});

  if (!db.cardTopups) db.cardTopups = [];

  const card = db.cardTopups.find(x => x.id === req.params.id);

  if (!card)
    return res.status(404).json({error:"Không tìm thấy đơn thẻ"});

  if (card.status !== "pending")
    return res.status(400).json({error:"Đơn này đã được xử lý"});

  card.status = "rejected";
  card.rejectedAt = new Date().toISOString();
  card.rejectedBy = req.user.username;

  save(db);

  res.json({
    ok:true,
    message:"Đã từ chối đơn thẻ"
  });
});


app.listen(PORT,"0.0.0.0",()=>console.log(`Damon Store V5 running on port ${PORT}`));
