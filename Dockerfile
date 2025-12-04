FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install solc
RUN pip install solc-select && \
    solc-select install 0.8.19 && \
    solc-select use 0.8.19

# Copy requirements first for caching
COPY requirements-minimal.txt .
RUN pip install --no-cache-dir -r requirements-minimal.txt

# Install slither
RUN pip install slither-analyzer

# Copy application code
COPY . .

# Expose port 7860 (Hugging Face default)
EXPOSE 7860

# Run the server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "7860"]
