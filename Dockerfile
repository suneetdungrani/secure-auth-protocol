FROM ubuntu:22.04

# Author: Suneet Dungrani
LABEL maintainer="Suneet Dungrani"
LABEL description="Formal verification environment for secure authentication protocol"

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install base dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    openjdk-17-jre-headless \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install TLA+ tools
WORKDIR /opt/tla
RUN wget https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar && \
    echo '#!/bin/bash\njava -jar /opt/tla/tla2tools.jar "$@"' > /usr/local/bin/tlc && \
    chmod +x /usr/local/bin/tlc

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Make scripts executable
RUN chmod +x scripts/*.sh 2>/dev/null || true

# Create non-root user
RUN useradd -m -s /bin/bash verifier && \
    chown -R verifier:verifier /app

USER verifier

# Set environment variables
ENV PYTHONPATH=/app/src
ENV TLA2TOOLS_JAR=/opt/tla/tla2tools.jar

# Default command
CMD ["/bin/bash", "-c", "echo 'Secure Authentication Protocol Verification Environment' && echo 'Author: Suneet Dungrani' && echo '' && echo 'Available commands:' && echo '  - Run tests: python3 -m pytest tests/' && echo '  - Run TLA+ verification: ./scripts/verify.sh' && echo '  - Start server: python3 src/server.py' && echo '  - Run client: python3 src/client.py' && echo '' && /bin/bash"]