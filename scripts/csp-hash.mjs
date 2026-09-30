// Пересчитывает Content-Security-Policy для встроенных <style> и <script> в страницах сайта.
// Браузер выполнит только тот CSS и JS, чей SHA-256 совпадает с хэшем в политике,
// поэтому после ЛЮБОЙ правки стилей или скрипта запустите:  node scripts/csp-hash.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const PAGES = ['index.html', '404.html'];

// Парсер HTML сводит переводы строк к \n до подсчёта хэша — делаем так же
const hash = (s) => `'sha256-${createHash('sha256').update(s.replace(/\r\n?/g, '\n'), 'utf8').digest('base64')}'`;
const pick = (html, tag) => (html.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`)) || [])[1];
const META = /(<meta http-equiv="Content-Security-Policy" content=")[^"]*(")/;

for (const page of PAGES) {
  const file = new URL(`../${page}`, import.meta.url);
  let html = readFileSync(file, 'utf8');
  const style = pick(html, 'style');
  const script = pick(html, 'script');
  const csp = [
    "default-src 'none'",                                  // по умолчанию запрещено всё: никаких внешних запросов
    script !== undefined && `script-src ${hash(script)}`,  // только наш встроенный скрипт
    style !== undefined && `style-src ${hash(style)}`,     // только наши встроенные стили
    'img-src data:',                                       // иконка вкладки встроена как data:
    "base-uri 'none'",
    "form-action 'none'",
  ].filter(Boolean).join('; ');
  if (!META.test(html)) throw new Error(`${page}: не найден <meta http-equiv="Content-Security-Policy">`);
  html = html.replace(META, `$1${csp}$2`);
  writeFileSync(file, html);
  console.log(`${page}:\n  ${csp.split('; ').join('\n  ')}`);
}
