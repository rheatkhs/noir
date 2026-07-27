# Example Vulnerable Targets

Local test targets for validating Noir skills.

---

## OWASP Juice Shop

Modern insecure web application for security training.

```bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```

Target: `http://localhost:3000`

---

## DVWA (Damn Vulnerable Web Application)

PHP/MySQL web app for practicing common vulnerabilities.

```bash
docker pull vulnerables/web-dvwa
docker run -d -p 8080:80 vulnerables/web-dvwa
```

Target: `http://localhost:8080`  
Login: `admin` / `password`

---

## WebGoat

Intentionally insecure web application by OWASP.

```bash
docker pull webgoat/goatandwolf
docker run -d -p 8080:8080 -p 9090:9090 webgoat/goatandwolf
```

Target: `http://localhost:8080/WebGoat`

---

## VulHub

Pre-built vulnerable environments for specific CVEs and misconfigurations.

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/<environment>
docker compose up -d
```

Environments: https://github.com/vulhub/vulhub

---

## HackTheBox

Weekly updated vulnerable machines (requires subscription).

```bash
# Connect via OpenVPN
sudo openvpn lab.ovpn

# Target IP provided after machine spawn
nmap -sV <target-ip>
```

Website: https://www.hackthebox.com

---

## TryHackMe

Guided vulnerable rooms for all skill levels (free tier available).

```bash
# Connect via OpenVPN
sudo openvpn config.ovpn

# Target IP provided in room
nmap -sV <target-ip>
```

Website: https://tryhackme.com

---

## CRLF Injection Test

Simple local server for testing CRLF injection:

```bash
python3 -m http.server 8000
```

Target: `http://localhost:8000`

---

## Local API Server (Express)

```bash
mkdir test-api && cd test-api
npm init -y
npm install express
cat > index.js << 'EOF'
const express = require('express');
const app = express();
app.get('/api/user/:id', (req, res) => {
  res.json({ id: req.params.id, name: 'test' });
});
app.post('/api/login', express.json(), (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin') {
    return res.json({ token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' });
  }
  res.status(401).json({ error: 'invalid credentials' });
});
app.listen(3000);
EOF
node index.js
```

Target: `http://localhost:3000`
