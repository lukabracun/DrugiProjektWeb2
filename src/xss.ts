import { escapeHtml } from "./views";

export const comments: string[] = [];
export const stolen: { time: string; data: string }[] = [];

export function renderComments(vulnerable: boolean): string {
    if (comments.length === 0) {
        return "<p>Nema komentara.</p>";
    }
    const items = comments
        .map((c) => `<li>${vulnerable ? c : escapeHtml(c)}</li>`)
        .join("\n");
    return `<ul>\n${items}\n</ul>`;
}