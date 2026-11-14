import express from "express";
import cookieParser from "cookie-parser";
import { layout, toggle, Settings } from "./views";

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

app.get("/", (req, res) => {
    const s = readSettings(req);
    res.send(layout(`
<hr>
<h2>Cross-site scripting (XSS)</h2>
${toggle("xss", s.xss)}
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

app.listen(port, () => {
    console.log(`Server: http://localhost:${port}`);
});