import crypto from "crypto";
import { escapeHtml } from "./views";

type PlainUser = { username: string; password: string; card: string };
type SecureUser = { username: string; salt: string; hash: string; card: string };

const plainUsers: PlainUser[] = [];
const secureUsers: SecureUser[] = [];

const key = process.env.DATA_KEY
    ? Buffer.from(process.env.DATA_KEY, "hex")
    : crypto.randomBytes(32);

function hashPassword(password: string, salt: string): string {
    return crypto.scryptSync(password, salt, 64).toString("hex");
}

function encrypt(text: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString("hex")}:${tag.toString("hex")}:${ct.toString("hex")}`;
}

function decrypt(data: string): string {
    const [iv, tag, ct] = data.split(":").map((p) => Buffer.from(p, "hex"));
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

function maskCard(card: string): string {
    return "**** **** **** " + card.slice(-4);
}

export function register(vulnerable: boolean, username: string, password: string, card: string): string {
    const digits = card.replace(/\s/g, "");
    if (!username || !password || !/^\d{13,19}$/.test(digits)) {
        return "Neispravni podaci. Broj kartice mora imati između 13 i 19 znamenki.";
    }
    if (vulnerable) {
        if (plainUsers.some((u) => u.username === username)) {
            return "Korisnik već postoji.";
        }
        plainUsers.push({ username, password, card: digits });
    } else {
        if (secureUsers.some((u) => u.username === username)) {
            return "Korisnik već postoji.";
        }
        const salt = crypto.randomBytes(16).toString("hex");
        secureUsers.push({ username, salt, hash: hashPassword(password, salt), card: encrypt(digits) });
    }
    return `Korisnik ${username} je registriran.`;
}

export function login(vulnerable: boolean, username: string, password: string): string {
    const failed = "Pogrešno korisničko ime ili lozinka.";
    if (vulnerable) {
        const u = plainUsers.find((u) => u.username === username && u.password === password);
        return u ? `Prijava uspješna (${u.username}). Broj kartice: ${u.card}` : failed;
    }
    const u = secureUsers.find((u) => u.username === username);
    if (!u) {
        return failed;
    }
    const candidate = Buffer.from(hashPassword(password, u.salt), "hex");
    if (!crypto.timingSafeEqual(candidate, Buffer.from(u.hash, "hex"))) {
        return failed;
    }
    return `Prijava uspješna (${u.username}). Broj kartice: ${maskCard(decrypt(u.card))}`;
}

export function renderDatabase(vulnerable: boolean): string {
    if (vulnerable) {
        const rows = plainUsers
            .map((u) => `<tr><td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.password)}</td><td>${u.card}</td></tr>`)
            .join("\n");
        return `<table border="1">
<tr><th>username</th><th>password</th><th>card</th></tr>
${rows}
</table>`;
    }
    const rows = secureUsers
        .map((u) => `<tr><td>${escapeHtml(u.username)}</td><td>${u.salt}</td><td>${u.hash}</td><td>${u.card}</td></tr>`)
        .join("\n");
    return `<table border="1">
<tr><th>username</th><th>salt</th><th>password_hash (scrypt)</th><th>card (AES-256-GCM, iv:tag:ciphertext)</th></tr>
${rows}
</table>`;
}

for (const [username, password, card] of [
    ["ana", "ana123", "4111111111111111"],
    ["marko", "lozinka", "5555555555554444"],
]) {
    register(true, username, password, card);
    register(false, username, password, card);
}