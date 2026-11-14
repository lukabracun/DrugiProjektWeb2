import express from "express";

const app = express();
const port = Number(process.env.PORT) || 3000;

app.get("/", (_req, res) => {
    res.send("<h1>Drugi projekt</h1>");
});

app.listen(port, () => {
    console.log(`Server: http://localhost:${port}`);
});