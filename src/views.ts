export type Settings = { xss: boolean; sde: boolean };

export function layout(body: string): string {
    return `<!DOCTYPE html>
<html lang="hr">
<head>
<meta charset="utf-8">
<title>Drugi projekt</title>
</head>
<body>
<h1>Drugi projekt</h1>
${body}
</body>
</html>`;
}

export function toggle(name: keyof Settings, enabled: boolean): string {
    return `<form method="post" action="/settings/${name}">
<input type="checkbox" name="enabled" ${enabled ? "checked" : ""}> Ranjivost uključena
<button type="submit">Primijeni</button>
</form>`;
}

export function escapeHtml(s: string): string {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}