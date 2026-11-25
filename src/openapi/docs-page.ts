export function apiDocsPage(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Credimi Capture Wallet API</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="stylesheet" href="https://unpkg.com/@stoplight/elements@9.0.0/styles.min.css">
  </head>
  <body>
    <elements-api apiDescriptionUrl="/openapi.json" layout="responsive" router="hash"></elements-api>
    <script src="https://unpkg.com/@stoplight/elements@9.0.0/web-components.min.js"></script>
  </body>
</html>`;
}
