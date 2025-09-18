# Use an official Python runtime as the base image
FROM python:3.11-slim

# Prevents Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

# Set working directory inside the container
WORKDIR /app

# Copy requirements.txt first (for faster builds)
COPY requirements.txt /app/

# Install dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy all project files into container
COPY . /app/

# Expose port 8000 for Django
EXPOSE 8000

# Default command: run Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
