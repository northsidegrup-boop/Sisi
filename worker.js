const json = (data, status=200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type":"application/json; charset=utf-8",
  "cache-control":"no-store", "access-control-allow-origin":"same-origin" }
});
const clean = (s, max=5000) => String(s ?? "").trim().slice(0,max);
const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function digest(s) { return hex(await crypto.subtle.digest("SHA-256",enc.encode(s))); }
async function passwordHash(password,salt) {
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:180000,hash:"SHA-256"},key,256);
  return hex(bits);
}
function cookie(req) {
  const raw=req.headers.get("Cookie")||"";
  return raw.split(";").map(x=>x.trim()).find(x=>x.startsWith("ns_session="))?.slice(11)||"";
}
async function currentUser(req,env) {
  const token=cookie(req); if(!token) return null;
  const hash=await digest(token);
  const row=await env.DB.prepare(`SELECT users.id,username,email,role,points,featured
    FROM sessions JOIN users ON users.id=sessions.user_id
    WHERE token_hash=? AND expires_at>?`).bind(hash,Date.now()).first();
  return row||null;
}
const authCookie = token => `ns_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`;
async function requireUser(req,env) {
  const user=await currentUser(req,env);
  return user;
}
async function requireAdmin(req,env) {
  const user=await currentUser(req,env);
  return user?.role==="admin" ? user : null;
}
async function api(req,env) {
  const url=new URL(req.url), path=url.pathname, method=req.method;
  if(method==="GET" && path==="/api/me") return json({user:await currentUser(req,env)});
  if(method==="POST" && path==="/api/register") {
    const d=await req.json(), username=clean(d.username,24), email=clean(d.email,120).toLowerCase(), password=String(d.password||"");
    if(!/^[\p{L}\p{N}_ -]{3,24}$/u.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<10)
      return json({error:"Revisa tus datos. La contraseña debe tener al menos 10 caracteres."},400);
    const salt=crypto.randomUUID(), hash=await passwordHash(password,salt);
    const role=email===String(env.ADMIN_EMAIL||"").toLowerCase() ? "admin" : "member";
    try {
      const result=await env.DB.prepare("INSERT INTO users(username,email,password_hash,salt,role) VALUES(?,?,?,?,?)")
        .bind(username,email,hash,salt,role).run();
      const token=crypto.randomUUID()+crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)")
        .bind(await digest(token),result.meta.last_row_id,Date.now()+604800000).run();
      return new Response(JSON.stringify({ok:true}),{headers:{"content-type":"application/json","set-cookie":authCookie(token)}});
    } catch(e) { return json({error:"Ese usuario o correo ya está registrado."},409); }
  }
  if(method==="POST" && path==="/api/login") {
    const d=await req.json(), email=clean(d.email,120).toLowerCase(), password=String(d.password||"");
    const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    if(!u || await passwordHash(password,u.salt)!==u.password_hash) return json({error:"Correo o contraseña incorrectos."},401);
    const token=crypto.randomUUID()+crypto.randomUUID();
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)")
      .bind(await digest(token),u.id,Date.now()+604800000).run();
    return new Response(JSON.stringify({ok:true}),{headers:{"content-type":"application/json","set-cookie":authCookie(token)}});
  }
  if(method==="POST" && path==="/api/logout") {
    const token=cookie(req); if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return new Response(JSON.stringify({ok:true}),{headers:{"content-type":"application/json","set-cookie":"ns_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"}});
  }
  if(method==="GET" && path==="/api/members") {
    const {results=[]}=await env.DB.prepare("SELECT id,username,role,points,featured,created_at FROM users ORDER BY created_at DESC").all();
    return json({members:results});
  }
  if(method==="GET" && path==="/api/ranking") {
    const {results=[]}=await env.DB.prepare("SELECT id,username,points,featured FROM users ORDER BY points DESC,username ASC LIMIT 20").all();
    return json({ranking:results});
  }
  if(method==="GET" && path==="/api/topics") {
    const {results=[]}=await env.DB.prepare(`SELECT topics.id,title,body,topics.created_at,users.username,
      (SELECT COUNT(*) FROM replies WHERE replies.topic_id=topics.id) replies
      FROM topics JOIN users ON users.id=topics.user_id ORDER BY topics.created_at DESC LIMIT 50`).all();
    return json({topics:results});
  }
  if(method==="POST" && path==="/api/topics") {
    const user=await requireUser(req,env); if(!user) return json({error:"Inicia sesión para publicar."},401);
    const d=await req.json(), title=clean(d.title,100), body=clean(d.body,3000);
    if(title.length<4||body.length<2) return json({error:"Escribe un título y un mensaje."},400);
    await env.DB.prepare("INSERT INTO topics(user_id,title,body) VALUES(?,?,?)").bind(user.id,title,body).run();
    return json({ok:true});
  }
  const replyMatch=path.match(/^\/api\/topics\/(\d+)\/replies$/);
  if(method==="GET" && replyMatch) {
    const {results=[]}=await env.DB.prepare(`SELECT replies.id,body,replies.created_at,users.username FROM replies
      JOIN users ON users.id=replies.user_id WHERE topic_id=? ORDER BY replies.created_at ASC`).bind(replyMatch[1]).all();
    return json({replies:results});
  }
  if(method==="POST" && replyMatch) {
    const user=await requireUser(req,env); if(!user) return json({error:"Inicia sesión para responder."},401);
    const d=await req.json(), body=clean(d.body,2000);
    if(body.length<2) return json({error:"La respuesta está vacía."},400);
    await env.DB.prepare("INSERT INTO replies(topic_id,user_id,body) VALUES(?,?,?)").bind(replyMatch[1],user.id,body).run();
    return json({ok:true});
  }
  if(method==="PATCH" && path.startsWith("/api/admin/users/")) {
    const admin=await requireAdmin(req,env); if(!admin) return json({error:"No autorizado."},403);
    const id=Number(path.split("/").pop()), d=await req.json();
    const points=Math.max(0,Math.min(100000,Number(d.points)||0)), featured=d.featured?1:0;
    await env.DB.prepare("UPDATE users SET points=?,featured=? WHERE id=?").bind(points,featured,id).run();
    return json({ok:true});
  }
  if(method==="DELETE" && path.startsWith("/api/admin/topics/")) {
    const admin=await requireAdmin(req,env); if(!admin) return json({error:"No autorizado."},403);
    await env.DB.prepare("DELETE FROM topics WHERE id=?").bind(Number(path.split("/").pop())).run();
    return json({ok:true});
  }
  return json({error:"Ruta no encontrada."},404);
}
export default {
  async fetch(req,env) {
    const url=new URL(req.url);
    if(url.pathname.startsWith("/api/")) {
      if(req.method==="OPTIONS") return new Response(null,{headers:{"access-control-allow-origin":"same-origin","access-control-allow-methods":"GET,POST,PATCH,DELETE,OPTIONS","access-control-allow-headers":"content-type"}});
      try { return await api(req,env); } catch(e) { return json({error:"Error interno del servidor."},500); }
    }
    return env.ASSETS.fetch(req);
  }
};
