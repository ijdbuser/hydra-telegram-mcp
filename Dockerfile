# Use an official Python runtime as a parent image (Alpine-based for minimal vulnerabilities)
FROM python:3.13-alpine

# Set the working directory in the container
WORKDIR /app

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Ensure Python output is sent straight to terminal (useful for logs)
ENV PYTHONUNBUFFERED=1

# Copy dependency definition files
# If using Poetry:
# COPY pyproject.toml poetry.lock* ./
# RUN pip install --no-cache-dir poetry
# RUN poetry config virtualenvs.create false && poetry install --no-dev --no-interaction --no-ansi
# If using pip with requirements.txt:
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY main.py sanitize.py ./
COPY telegram_mcp ./telegram_mcp
# COPY session_string_generator.py . # Optional: if needed within the container, otherwise can be run outside

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser:appuser /app
USER appuser

# Telegram credentials and session configuration must be provided at runtime,
# for example through docker-compose env_file, docker run -e, or CI variables.

# Expose the default FastMCP streamable HTTP port.
EXPOSE 8000

# Define the command to run the application
CMD ["python", "main.py"]
