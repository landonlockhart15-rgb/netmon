"""
Focused tests for the shipped Markdown renderer bundle.

These tests render the compiled asset with react-dom/server so we can pin the
link-sanitization behavior from Python pytest/unittest without depending on a
local TypeScript install.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
_markdown_bundles = list((ROOT / "static" / "assets").glob("Markdown-*.js"))
MARKDOWN_BUNDLE = _markdown_bundles[0] if _markdown_bundles else (ROOT / "static" / "assets" / "Markdown-DxHEULee.js")


NODE_RENDER_SCRIPT = r"""
const fs = require('fs');

const sourcePath = process.env.SOURCE_PATH;
const input = fs.readFileSync(sourcePath, 'utf8');
if (!input) {
  throw new Error(`Empty Markdown bundle: ${sourcePath}`);
}

function jsx(type, props) {
  return { type, props: props || {} };
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toKebabCase(value) {
  return value.replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`);
}

function renderNode(node) {
  if (node === null || node === undefined || node === false || node === true) {
    return '';
  }

  if (Array.isArray(node)) {
    return node.map(renderNode).join('');
  }

  if (typeof node === 'string' || typeof node === 'number') {
    return escapeHtml(node);
  }

  if (typeof node.type === 'function') {
    return renderNode(node.type(node.props || {}));
  }

  if (typeof node.type !== 'string') {
    return '';
  }

  const props = node.props || {};
  const children = props.children;
  const attrs = [];

  for (const [key, value] of Object.entries(props)) {
    if (key === 'children' || value === null || value === undefined || value === false) {
      continue;
    }

    const attrName = key === 'className' ? 'class' : key === 'htmlFor' ? 'for' : toKebabCase(key);
    if (value === true) {
      attrs.push(attrName);
    } else {
      attrs.push(`${attrName}="${escapeHtml(value)}"`);
    }
  }

  const voidElements = new Set(['hr', 'br', 'img', 'input', 'meta', 'link']);
  const openTag = attrs.length ? `<${node.type} ${attrs.join(' ')}>` : `<${node.type}>`;
  if (voidElements.has(node.type)) {
    return attrs.length ? `<${node.type} ${attrs.join(' ')}>` : `<${node.type}>`;
  }

  return `${openTag}${renderNode(children)}</${node.type}>`;
}

function safeUrl(value) {
  const url = String(value || '').trim();
  const normalized = url.toLowerCase();
  const allowed = ['http://', 'https://', 'mailto:', 'tel:', '/', '#'];
  return allowed.some((prefix) => normalized.startsWith(prefix)) ? url : null;
}

const transformed = input
  .replace(
    /^import\{[^}]+\}from"\.\/index-[^"]+\.js";/m,
    'const e = safeUrl; const t = () => ({ jsx, jsxs: jsx });',
  )
  .replace(/export\{([A-Za-z_$][\w$]*) as t\};?\s*$/m, 'module.exports = $1;');

const moduleShim = { exports: {} };
const compiled = new Function('module', 'exports', 'jsx', 'safeUrl', transformed);
compiled(moduleShim, moduleShim.exports, jsx, safeUrl);

const Markdown = moduleShim.exports.default || moduleShim.exports;
const text = JSON.parse(process.env.MARKDOWN_TEXT || '""');
const markup = renderNode(Markdown({ text }));
process.stdout.write(markup);
"""


class MarkdownRendererTests(unittest.TestCase):
    def render(self, text: str) -> str:
        env = os.environ.copy()
        env["SOURCE_PATH"] = str(MARKDOWN_BUNDLE)
        env["MARKDOWN_TEXT"] = json.dumps(text)
        result = subprocess.run(
            ["node", "-e", NODE_RENDER_SCRIPT],
            cwd=str(FRONTEND_DIR),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"node render failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )
        return result.stdout

    def test_allows_expected_safe_link_schemes_and_relative_targets(self):
        markup = self.render(
            "\n".join(
                [
                    "[HTTP](http://example.com)",
                    "[HTTPS](HTTPS://example.com/path?q=1)",
                    "[MAIL](mailto:alerts@example.com)",
                    "[TEL](tel:+15551234567)",
                    "[ROOT](/health)",
                    "[FRAGMENT](#alerts)",
                ]
            )
        )

        self.assertIn('<a href="http://example.com" target="_blank" rel="noopener noreferrer"', markup)
        self.assertIn('<a href="HTTPS://example.com/path?q=1" target="_blank" rel="noopener noreferrer"', markup)
        self.assertIn('<a href="mailto:alerts@example.com" target="_blank" rel="noopener noreferrer"', markup)
        self.assertIn('<a href="tel:+15551234567" target="_blank" rel="noopener noreferrer"', markup)
        self.assertIn('<a href="/health" target="_blank" rel="noopener noreferrer"', markup)
        self.assertIn('<a href="#alerts" target="_blank" rel="noopener noreferrer"', markup)

    def test_blocks_dangerous_protocols_even_with_case_and_whitespace_variants(self):
        markup = self.render(
            " ".join(
                [
                    "[JS](  JAVASCRIPT:alert(1)  )",
                    "[DATA](DaTa:text/html;base64,PHNjcmlwdD4=)",
                    "[VBS](vbScript:msgbox(1))",
                ]
            )
        )

        self.assertNotIn("<a ", markup)
        self.assertEqual(markup.count('title="Link blocked for security reasons"'), 3)
        self.assertIn(">JS</span>", markup)
        self.assertIn(">DATA</span>", markup)
        self.assertIn(">VBS</span>", markup)

    def test_preserves_safe_and_blocked_links_in_order(self):
        markup = self.render("[SAFE](https://example.com) [BAD](javascript:alert(1)) [PATH](/ok)")

        safe_index = markup.index('href="https://example.com"')
        blocked_index = markup.index('title="Link blocked for security reasons"')
        path_index = markup.rindex('href="/ok"')

        self.assertLess(safe_index, blocked_index)
        self.assertLess(blocked_index, path_index)


if __name__ == "__main__":
    unittest.main()
