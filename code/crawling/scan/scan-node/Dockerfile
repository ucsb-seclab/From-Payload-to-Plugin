# Start with the official Ubuntu base image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 python3-pip \
    curl tmux bash gnupg redis-tools jq \
    xvfb && \
    rm -rf /var/lib/apt/lists/*

# Add Google Chrome's official repository and install Chrome
RUN curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-linux-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-linux-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && \
    apt-get update && apt-get install -y --no-install-recommends google-chrome-stable && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies globally
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Set the working directory
WORKDIR /app

# Copy all the necessary files into the container
COPY . /app/

# Make run.sh executable
RUN chmod +x /app/run.sh

# Default command to run the bash script
CMD ["./run.sh"]
