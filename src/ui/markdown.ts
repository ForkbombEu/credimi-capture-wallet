import { escapeHtml } from "./html.js";
export function renderMarkdown(markdown: string): string {
  const html: string[] = [];
  let listOpen = false;
  let codeOpen = false;
  let paragraph: string[] = [];

  function flushParagraph(): void {
    if (paragraph.length === 0) return;
    html.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
    paragraph = [];
  }

  function closeList(): void {
    if (!listOpen) return;
    html.push("</ul>");
    listOpen = false;
  }

  for (const line of markdown.split(/\r?\n/)) {
    if (line.startsWith("```")) {
      flushParagraph();
      closeList();
      if (codeOpen) {
        html.push("</code></pre>");
        codeOpen = false;
      } else {
        html.push("<pre><code>");
        codeOpen = true;
      }
      continue;
    }

    if (codeOpen) {
      html.push(escapeHtml(line), "\n");
      continue;
    }

    const trimmed = line.trim();
    if (!trimmed) {
      flushParagraph();
      closeList();
      continue;
    }

    const heading = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushParagraph();
      closeList();
      const level = heading[1].length;
      html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }

    if (trimmed.startsWith("- ")) {
      flushParagraph();
      if (!listOpen) {
        html.push("<ul>");
        listOpen = true;
      }
      html.push(`<li>${inlineMarkdown(trimmed.slice(2))}</li>`);
      continue;
    }

    paragraph.push(trimmed);
  }

  flushParagraph();
  closeList();
  if (codeOpen) html.push("</code></pre>");
  return html.join("");
}

function inlineMarkdown(value: string): string {
  return escapeHtml(value).replace(/`([^`]+)`/g, "<code>$1</code>");
}
