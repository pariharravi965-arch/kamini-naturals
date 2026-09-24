const express = require('express');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const ROOT = __dirname;
const db = new Database(path.join(ROOT, 'data', 'kamini_naturals.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id TEXT UNIQUE NOT NULL,
 razorpay_order_id TEXT,
 payment_id TEXT,
 payment_signature TEXT,
 name TEXT NOT NULL,
 mobile TEXT NOT NULL,
 address TEXT NOT NULL,
 pin TEXT NOT NULL,
 items_json TEXT NOT NULL,
 product_total INTEGER NOT NULL,
 shipping INTEGER NOT NULL DEFAULT 0,
 grand_total INTEGER NOT NULL,
 payment_method TEXT NOT NULL,
 payment_status TEXT NOT NULL DEFAULT 'created',
 order_status TEXT NOT NULL DEFAULT 'PLACED',
 tracking_number TEXT,
 courier TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
`);

const products = [
['neem-daatun','Neem Daatun','नीम दातुन','Azadirachta indica',399,519,'दातुन','01_Neem_Daatun.jpg'],
['palash-bark','Palash Bark','पलाश छाल','Butea monosperma',599,778,'छाल','02_Palash_Bark.jpg'],
['babool-bark','Babool Bark','बबूल छाल','Vachellia nilotica',599,778,'छाल','03_Babool_Bark.jpg'],
['neem-bark','Neem Bark','नीम छाल','Azadirachta indica',549,714,'छाल','04_Neem_Bark.jpg'],
['neem-leaves','Neem Leaves','नीम पत्ती','Azadirachta indica',499,649,'पत्तियाँ','05_Neem_Leaves.jpg'],
['mehendi','Mehendi','मेहंदी','Lawsonia inermis',449,583,'पत्तियाँ','06_Mehendi.jpg'],
['giloy-stem','Giloy Stem','गिलोय तना','Tinospora cordifolia',599,778,'जड़/तना','07_Giloy_Stem.jpg'],
['amla','Amla','आंवला','Phyllanthus emblica',499,649,'फल','08_Amla.jpg'],
['harad','Harad','हरड़','Terminalia chebula',499,649,'फल','09_Harad.jpg'],
['moringa-leaves','Moringa Leaves','सहजना पत्ती','Moringa oleifera',599,778,'पत्तियाँ','10_Moringa_Leaves.jpg'],
['behada','Behada','बहेड़ा','Terminalia bellirica',499,649,'फल','11_Behada.jpg'],
['arjun-bark','Arjun Bark','अर्जुन छाल','Terminalia arjuna',699,908,'छाल','12_Arjun_Bark.jpg']
].map(x=>({id:x[0],en:x[1],hi:x[2],sci:x[3],price:x[4],mrp:x[5],cat:x[6],img:x[7],pack:'500 g'}));

app.use('/api/payments/webhook', express.raw({type:'application/json', limit:'1mb'}));
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:true}));
app.disable('x-powered-by');
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','SAMEORIGIN');next()});
app.use(express.static(path.join(ROOT,'public')));

function now(){return new Date().toISOString()}
function orderCode(){return 'KN'+Date.now().toString().slice(-8)+crypto.randomBytes(2).toString('hex').toUpperCase()}
function clean(s,max=500){return String(s??'').trim().slice(0,max)}
function validMobile(s){return /^\d{10}$/.test(s)}
function validPin(s){return /^\d{6}$/.test(s)}
const rateBuckets=new Map();
function rateLimit(key,limit,windowMs){
 const nowMs=Date.now(); let b=rateBuckets.get(key);
 if(!b||nowMs-b.start>=windowMs){b={start:nowMs,count:0};rateBuckets.set(key,b)}
 b.count++; return b.count<=limit;
}
function clientKey(req){return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim().slice(0,80)}
function sensitiveRate(req,res,next){
 const key=clientKey(req)+'|'+req.path;
 if(!rateLimit(key,20,60_000)) return res.status(429).json({error:'Too many requests. Please try again later.'});
 next();
}
function totalFor(items){
 let total=0, normalized=[];
 for(const it of Array.isArray(items)?items:[]){
  const p=products.find(x=>x.id===it.id); const qty=Math.max(1,Math.min(99,Number(it.qty)||0));
  if(!p||!qty) continue;
  total += p.price*qty; normalized.push({id:p.id,name:p.en,qty,unit_price:p.price,line_total:p.price*qty,pack:p.pack});
 }
 return {total,items:normalized};
}
function auth(req,res,next){
 const expected=process.env.ADMIN_TOKEN;
 if(!expected) return res.status(503).json({error:'ADMIN_TOKEN is not configured'});
 const got=req.headers.authorization?.replace(/^Bearer\s+/i,'');
 if(!got || got.length!==expected.length || !crypto.timingSafeEqual(Buffer.from(got),Buffer.from(expected))) return res.status(401).json({error:'Unauthorized'});
 next();
}

app.get('/api/config',(req,res)=>res.json({razorpayKeyId:process.env.RAZORPAY_KEY_ID||null, shippingFlat:Number(process.env.SHIPPING_FLAT||0), paymentEnabled:!!(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET)}));
app.get('/api/products',(req,res)=>res.json(products));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'kamini-naturals',time:now()}));

app.post('/api/orders/quote',(req,res)=>{
 const {total,items}=totalFor(req.body.items); const shipping=Math.max(0,Number(process.env.SHIPPING_FLAT||0));
 res.json({items,product_total:total,shipping,grand_total:total+shipping,currency:'INR'});
});

app.post('/api/orders/create',sensitiveRate,async(req,res)=>{
 try{
  const name=clean(req.body.name,120), mobile=clean(req.body.mobile,20), address=clean(req.body.address,1000), pin=clean(req.body.pin,6), paymentMethod=clean(req.body.payment_method,80);
  if(!name||!validMobile(mobile)||!address||!validPin(pin)) return res.status(400).json({error:'Invalid customer details'});
  if(!['UPI','CARD','NETBANKING'].includes(paymentMethod)) return res.status(400).json({error:'Only online payment methods are enabled'});
  const q=totalFor(req.body.items); if(!q.items.length) return res.status(400).json({error:'Cart is empty'});
  const shipping=Math.max(0,Number(process.env.SHIPPING_FLAT||0)); const grand=q.total+shipping; const orderId=orderCode();
  let razor=null;
  if(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET){
   const auth=Buffer.from(process.env.RAZORPAY_KEY_ID+':'+process.env.RAZORPAY_KEY_SECRET).toString('base64');
   const r=await fetch('https://api.razorpay.com/v1/orders',{method:'POST',headers:{'Authorization':'Basic '+auth,'Content-Type':'application/json'},body:JSON.stringify({amount:Math.round(grand*100),currency:'INR',receipt:orderId,notes:{customer_name:name}})});
   if(!r.ok) return res.status(502).json({error:'Payment gateway order creation failed'});
   razor=await r.json();
  }
  const t=now();
  db.prepare(`INSERT INTO orders(order_id,razorpay_order_id,name,mobile,address,pin,items_json,product_total,shipping,grand_total,payment_method,payment_status,order_status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(orderId,razor?.id||null,name,mobile,address,pin,JSON.stringify(q.items),q.total,shipping,grand,paymentMethod,razor?'created':'gateway_not_configured','PLACED',t,t);
  res.json({orderId,amount:grand,currency:'INR',razorpayOrderId:razor?.id||null,razorpayKeyId:process.env.RAZORPAY_KEY_ID||null,items:q.items,shipping});
 }catch(e){console.error('Order creation failed',e);res.status(500).json({error:'Order creation failed'})}
});

app.post('/api/payments/verify',sensitiveRate,(req,res)=>{
 const {orderId,razorpay_order_id,razorpay_payment_id,razorpay_signature}=req.body;
 if(!orderId||!razorpay_order_id||!razorpay_payment_id||!razorpay_signature) return res.status(400).json({error:'Missing payment fields'});
 const row=db.prepare('SELECT * FROM orders WHERE order_id=?').get(orderId); if(!row) return res.status(404).json({error:'Order not found'});
 if(!process.env.RAZORPAY_KEY_SECRET || row.razorpay_order_id!==razorpay_order_id) return res.status(400).json({error:'Payment verification failed'});
 const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id+'|'+razorpay_payment_id).digest('hex');
 const expectedBuf=Buffer.from(expected,'utf8'), receivedBuf=Buffer.from(String(razorpay_signature),'utf8');
 if(expectedBuf.length!==receivedBuf.length || !crypto.timingSafeEqual(expectedBuf,receivedBuf)) return res.status(400).json({error:'Payment signature verification failed'});
 db.prepare('UPDATE orders SET payment_id=?,payment_signature=?,payment_status=?,order_status=?,updated_at=? WHERE order_id=?').run(razorpay_payment_id,razorpay_signature,'paid','PAID',now(),orderId);
 res.json({ok:true,orderId});
});

app.post('/api/payments/webhook',sensitiveRate,(req,res)=>{
 const secret=process.env.RAZORPAY_WEBHOOK_SECRET; if(!secret) return res.status(503).end();
 const signature=String(req.headers['x-razorpay-signature']||''); const raw=Buffer.isBuffer(req.body)?req.body:Buffer.from('');
 const expected=crypto.createHmac('sha256',secret).update(raw).digest('hex');
 const expectedBuf=Buffer.from(expected,'utf8'), receivedBuf=Buffer.from(signature,'utf8');
 if(!signature||expectedBuf.length!==receivedBuf.length||!crypto.timingSafeEqual(expectedBuf,receivedBuf)) return res.status(400).end();
 let body; try{body=JSON.parse(raw.toString('utf8'))}catch{return res.status(400).end()}
 const p=body.payload||{}; const entity=p.payment?.entity; const ro=p.order?.entity;
 const razorOrderId=entity?.order_id||ro?.id; const paymentId=entity?.id;
 if(razorOrderId){
  const status=body.event==='payment.captured'||body.event==='order.paid'?'paid':'updated';
  db.prepare('UPDATE orders SET payment_id=COALESCE(?,payment_id),payment_status=?,updated_at=? WHERE razorpay_order_id=?').run(paymentId,status,now(),razorOrderId);
 }
 res.json({ok:true});
});

app.get('/api/orders/track/:id',sensitiveRate,(req,res)=>{const r=db.prepare('SELECT order_id,product_total,shipping,grand_total,payment_method,payment_status,order_status,tracking_number,courier,created_at,updated_at,items_json FROM orders WHERE order_id=?').get(clean(req.params.id,50)); if(!r)return res.status(404).json({error:'Order not found'}); r.items=JSON.parse(r.items_json); delete r.items_json; res.json(r)});
app.get('/api/admin/orders',auth,(req,res)=>{const rows=db.prepare('SELECT * FROM orders ORDER BY id DESC LIMIT 200').all().map(r=>({...r,items:JSON.parse(r.items_json)})); res.json(rows)});
app.patch('/api/admin/orders/:id',auth,(req,res)=>{const order=clean(req.params.id,50); const allowedStatus=['PLACED','PAID','PROCESSING','PACKED','SHIPPED','DELIVERED','CANCELLED','REFUND_PENDING','REFUNDED']; const status=clean(req.body.order_status,30); if(!allowedStatus.includes(status)) return res.status(400).json({error:'Invalid status'}); db.prepare('UPDATE orders SET order_status=?,tracking_number=?,courier=?,updated_at=? WHERE order_id=?').run(status,clean(req.body.tracking_number,120)||null,clean(req.body.courier,80)||null,now(),order); res.json({ok:true});});

app.get('*',(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
app.listen(PORT,()=>console.log(`Kamini Naturals V3 running on http://127.0.0.1:${PORT}`));
