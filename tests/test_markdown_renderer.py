"""
Focused tests for frontend/src/components/shared/Markdown.tsx.

These tests transpile the TSX component on the fly and render it with
react-dom/server so we can pin the link-sanitization behavior from Python
pytest/unittest without modifying the frontend source tree.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
MARKDOWN_TSX = FRONTEND_DIR / "src" / "components" / "shared" / "Markdown.tsx"


NODE_RENDER_SCRIPT = r"""
const fs = require('fs');
const ts = require('typescript');
const React = require('react');
const ReactDOMServer = require('react-dom/server');

const sourcePath = process.env.SOURCE_PATH;
const input = fs.readFileSync(sourcePath, 'utf8');
const result = ts.transpileModule(input, {
  compilerOptions: {
    jsx: ts.JsxEmit.ReactJSX,
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020,
    esModuleInterop: true,
  },
  fileName: sourcePath,
});

const moduleShim = { exports: {} };
const compiled = new Function('require', 'exports', 'module', result.outputText);
compiled(require, moduleShim.exports, moduleShim);

const Markdown = moduleShim.exports.default || moduleShim.exports;
const text = JSON.parse(process.env.MARKDOWN_TEXT || '""');
const markup = ReactDOMServer.renderToStaticMarkup(React.createElement(Markdown, { text }));
process.stdout.write(markup);
"""


class MarkdownRendererTests(unittest.TestCase):
    def render(self, text: str) -> str:
        env = os.environ.copy()
        env["SOURCE_PATH"] = str(MARKDOWN_TSX)
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
