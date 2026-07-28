import os, sys, shutil, subprocess, platform

REQUIRED = {
    "nmap": "https://nmap.org",
    "curl": "https://curl.se",
    "ffuf": "https://github.com/ffuf/ffuf",
    "python3": "https://python.org",
}

PIP_PKGS = ["playwright", "requests", "mcp"]

def missing(name):
    return shutil.which(name) is None

def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r.returncode == 0, r.stdout.strip()

def main():
    sys.stderr.write("Noir — checking dependencies...\n")
    sys = platform.system().lower()

    missing_tools = [t for t in REQUIRED if missing(t)]
    if missing_tools:
        sys.stderr.write(f"missing: {', '.join(missing_tools)}\n")

    if "ffuf" in missing_tools:
        ffuf_ver = "2.1.0"
        arch = platform.machine()
        if sys == "linux":
            url = f"https://github.com/ffuf/ffuf/releases/download/v{ffuf_ver}/ffuf_{ffuf_ver}_linux_{arch}.tar.gz"
            ok, _ = run(["wget", "-qO-", url])
            if ok:
                run(["tar", "-xf", "-", "-C", "/usr/local/bin", "ffuf"])
        elif sys == "darwin":
            run(["brew", "install", "ffuf"])
        elif sys == "windows":
            url = f"https://github.com/ffuf/ffuf/releases/download/v{ffuf_ver}/ffuf_{ffuf_ver}_windows_{arch}.zip"
            zip_path = os.path.join(os.environ.get("TEMP", "/tmp"), "ffuf.zip")
            ok, _ = run(["curl", "-sL", url, "-o", zip_path])
            if ok:
                import zipfile
                with zipfile.ZipFile(zip_path) as z:
                    z.extract("ffuf.exe", "/usr/local/bin/" if os.name != "nt" else os.environ.get("LOCALAPPDATA", "."))
                os.remove(zip_path)

    if "nmap" in missing_tools:
        if sys == "linux":
            run(["apt-get", "install", "-y", "nmap"])
        elif sys == "darwin":
            run(["brew", "install", "nmap"])
        elif sys == "windows":
            run(["winget", "install", "Insecure.Nmap"], check=False)

    if "curl" in missing_tools:
        if sys == "linux":
            run(["apt-get", "install", "-y", "curl"])

    for pkg in PIP_PKGS:
        ok, out = run([sys.executable, "-m", "pip", "install", pkg])
        if not ok:
            sys.stderr.write(f"pip install {pkg} failed: {out}\n")

    ok, _ = run([sys.executable, "-m", "playwright", "install", "chromium"])
    if not ok:
        sys.stderr.write("playwright chromium install failed (non-fatal, browser tests disabled)\n")

    sys.stderr.write("Noir — ready.\n")

if __name__ == "__main__":
    main()
