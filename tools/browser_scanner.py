#!/usr/bin/env python3
"""
Noir Browser Scanner — Playwright-based browser security testing.
Usage: python tools/browser_scanner.py <target_url> [--auth <user:pass>] [--output <file>]
"""

import asyncio
import json
import sys
import time
import hashlib
import re
from urllib.parse import urlparse, urljoin
from pathlib import Path

from playwright.async_api import async_playwright

SCAN_PAYLOADS = {
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ],
    "sqli": [
        "' OR 1=1--",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' OR '1'='1",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "${{7*7}}",
        "<%= 7*7 %>",
    ],
}

VULN_PATTERNS = {
    "xss": [r"<script>.*alert", r"onerror=", r"onload=", r"javascript:"],
    "sqli": [r"sql syntax", r"mysql_fetch", r"ora-0", r"postgresql", "sqlite3", "syntax error"],
    "ssti": [r"49", r"49\.0", "7 * 7"],
    "lfi": [r"root:x:0:0", r"\[boot loader\]"],
}

XSS_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(", "innerText", "innerHTML"
]

class BrowserScanner:
    def __init__(self, target_url, auth=None, output_dir=None):
        self.target_url = target_url
        self.auth = auth
        self.output_dir = Path(output_dir) if output_dir else Path("noir_reports") / self._domain(target_url)
        self.visited = set()
        self.findings = []
        self.visited_hashes = set()
        self.browser = None
        self.context = None
        self.page = None

    def _domain(self, url):
        return urlparse(url).netloc.replace(":", "-")

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        self.page = await self.context.new_page()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.browser.close()
        await self.playwright.stop()

    async def navigate(self, url, timeout=30000):
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=timeout)
            return True
        except Exception as e:
            self._log_finding("nav_error", url, f"Navigation failed: {e}")
            return False

    async def login(self, login_url, username, password, username_selector="input[name='username'], input[name='email'], input[type='email']", password_selector="input[name='password'], input[type='password']", submit_selector="button[type='submit'], input[type='submit']"):
        """Attempt to log in."""
        await self.navigate(self.auth_url or self.target_url)
        try:
            await self.page.fill(username_selector, username)
            await self.page.fill(password_selector, password)
            await self.page.click(submit_selector)
            await self.page.wait_for_load_state("networkidle")
            return True
        except Exception as e:
            self._log_finding("login_failed", self.target_url, str(e))
            return False

    def _log_finding(self, vuln_type, endpoint, evidence, severity="medium", payload=None):
        finding = {
            "type": vuln_type,
            "endpoint": endpoint,
            "severity": severity,
            "evidence": evidence[:500],
            "payload": payload,
            "timestamp": time.time(),
        }
        self.findings.append(finding)
        print(f"[FINDING] {vuln_type} at {endpoint} ({severity})")

    async def scan_page(self, url):
        """Scan a single page for vulnerabilities."""
        if url in self.visited:
            return
        self.visited.add(url)

        # Check cache
        if not await self.navigate(url):
            return

        body_hash = hashlib.sha256(self.page.content().encode()).hexdigest()
        if url in self.visited_hashes and self.visited_hashes[url] == body_hash:
            print(f"  [SKIP] {url} (unchanged)")
            return
        self.visited_hashes[url] = body_hash

        # Wait for JS to execute
        await asyncio.sleep(2)

        # Extract forms
        forms = await self.page.query_selector_all("form")
        for form in await self.page.query_selector_all("form"):
            await self._test_form(form, url)

        # Check for DOM XSS sinks
        await self._check_dom_xss()

        # Check cookies
        await self._check_cookies()

        # Check CSP header
        await self._check_csp()

        # Check for clickjacking
        await self._check_clickjacking()

        # Check forms for CSRF tokens
        await self._check_csrf()

        # Extract links and recurse (same origin only)
        links = await self.page.query_selector_all("a[href]")
        for link in links[:20]:  # limit
            href = await link.get_attribute("href")
            if href:
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    await self.scan_page(full_url)

    async def _test_form(self, form, page_url):
        """Test a form for XSS and SQLi."""
        try:
            inputs = await form.query_selector_all("input, textarea, select")
            fields = []
            for inp in inputs:
                name = await inp.get_attribute("name")
                typ = await inp.get_attribute("type")
                if name and typ not in ("submit", "button", "hidden", "file"):
                    fields.append((name, typ))

            if not fields:
                return

            # Test XSS
            for payload in SCAN_PAYLOADS["xss"]:
                await self._submit_form(form, fields, payload, "xss")

            # Test SQLi
            for payload in SCAN_PAYLOADS["sqli"]:
                await self._submit_form(form, fields, payload, "sqli")

            # Test SSTI
            for payload in SCAN_PAYLOADS["ssti"]:
                await self._submit_form(form, fields, payload, "ssti")

        except Exception as e:
            self._log_finding("form_error", page_url, str(e))

    async def _submit_form(self, form, fields, payload, vuln_type):
        """Submit a form with a payload and check for vulnerability."""
        try:
            # Fill all fields with payload
            for name, typ in fields:
                try:
                    await self.page.fill(f"input[name='{name}'], textarea[name='{name}']", payload)
                except:
                    pass

            # Submit
            await self.page.evaluate("() => document.querySelector('form').submit()")
            await self.page.wait_for_load_state("networkidle", timeout=10000)

            content = await self.page.content()
            self._check_vuln_response(page_url, content, payload, vuln_type)

            # Go back
            await self.page.go_back()
            await self.page.wait_for_load_state("networkidle")

        except Exception as e:
            pass

    def _check_vuln_response(self, url, content, payload, vuln_type):
        content_lower = content.lower()
        payload_lower = payload.lower()

        if vuln_type == "xss":
            if payload in content and "<script>" in content_lower:
                self._log_finding("xss", url, f"Payload reflected: {payload}", "high", payload)
        elif vuln_type == "sqli":
            for pattern in VULN_PATTERNS["sqli"]:
                if pattern in content.lower():
                    self._log_finding("sqli", url, f"SQL error detected", "high", payload)
                    break
        elif vuln_type == "ssti":
            if "49" in content or "49.0" in content:
                self._log_finding("ssti", url, f"SSTI confirmed", "critical", payload)

    async def _check_dom_xss(self):
        """Check for DOM XSS sinks."""
        try:
            sinks = await self.page.evaluate("""
                () => {
                    const sinks = [];
                    const code = document.documentElement.outerHTML;
                    const sinks_list = ['innerHTML', 'outerHTML', 'document.write', 'document.writeln',
                        'eval(', 'setTimeout(', 'setInterval(', 'Function(', 'innerText', 'innerHTML'];
                    for (const sink of sinks_list) {
                        if (code.includes(sink)) sinks.push(sink);
                    }
                    return sinks;
                }
            """)
            for sink in sinks:
                self._log_finding("dom_xss_sink", self.page.url, f"Potential DOM XSS sink: {sink}", "medium")
        except:
            pass

    async def _check_cookies(self):
        cookies = await self.context.cookies()
        for cookie in cookies:
            issues = []
            if not cookie.get("httpOnly"):
                issues.append("HttpOnly: false")
            if not cookie.get("secure"):
                issues.append("Secure: false")
            if cookie.get("sameSite") not in ("Strict", "Lax"):
                issues.append(f"SameSite: {cookie.get('sameSite')}")
            if issues:
                self._log_finding("cookie_config", self.page.url,
                    f"Cookie '{cookie['name']}': {', '.join(issues)}", "low")

    async def _check_csp(self):
        """Check CSP headers."""
        try:
            response = await self.page.reload()
            headers = response.headers
            csp = headers.get("content-security-policy", "")
            if not csp:
                self._log_finding("missing_csp", self.page.url, "No Content-Security-Policy header", "medium")
            elif "unsafe-inline" in csp or "unsafe-eval" in csp:
                self._log_finding("weak_csp", self.page.url, f"Weak CSP: {csp}", "medium")
        except:
            pass

    async def _check_clickjacking(self):
        """Check for clickjacking protection."""
        try:
            response = await self.page.reload()
            headers = response.headers
            xfo = headers.get("x-frame-options", "")
            csp = headers.get("content-security-policy", "")
            if not xfo and "frame-ancestors" not in csp:
                self._log_finding("clickjacking", self.page.url,
                    "No X-Frame-Options or CSP frame-ancestors", "medium")
        except:
            pass

    async def _check_csrf(self):
        """Check forms for CSRF tokens."""
        try:
            forms = await self.page.query_selector_all("form")
            for form in forms:
                inputs = await form.query_selector_all("input[type='hidden']")
                has_csrf = False
                for inp in inputs:
                    name = await inp.get_attribute("name")
                    if name and "csrf" in name.lower():
                        has_csrf = True
                        break
                if not has_csrf:
                    self._log_finding("csrf", self.page.url,
                        "Form missing CSRF token", "low")
        except:
            pass

    async def scan(self, urls=None, max_pages=50):
        """Main scan loop."""
        urls = urls or [self.target_url]
        for url in urls:
            if len(self.visited) >= max_pages:
                break
            await self.scan_page(url)
        return self.findings

    def save_report(self):
        """Save findings to JSON."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report = {
            "target": self.target_url,
            "timestamp": time.time(),
            "findings": self.findings,
            "visited": list(self.visited),
        }
        out_file = self.output_dir / f"browser_scan_{int(time.time())}.json"
        with open(out_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {out_file}")
        return out_file


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Noir Browser Scanner")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--auth", help="username:password")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--max-pages", type=int, default=50)
    args = parser.parse_args()

    auth = None
    if args.auth:
        user, pwd = args.auth.split(":", 1)
        auth = (user, pwd)

    async with BrowserScanner(args.target, auth, args.output) as scanner:
        findings = await scanner.scan(max_pages=args.max_pages)
        report = scanner.save_report()

    print(f"\nScan complete. Found {len(scanner.findings)} findings.")
    print(f"Report saved to: {scanner.output_dir}")

if __name__ == "__main__":
    asyncio.run(main())