FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ffuf
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xf ffuf_2.1.0_linux_amd64.tar.gz -C /usr/local/bin ffuf \
    && rm ffuf_2.1.0_linux_amd64.tar.gz

# Install Python dependencies
RUN pip install --no-cache-dir playwright requests
RUN playwright install chromium && rm -rf /root/.cache/ms-playwright/*

WORKDIR /workspace

COPY . .

ENTRYPOINT ["python", "-m", "opencode"]
