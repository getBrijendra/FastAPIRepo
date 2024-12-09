# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the .env file into the container (optional, if it exists in your local directory)
COPY .env /app/.env

# Expose the port the app runs on
EXPOSE 8000

# Command to run the app using Uvicorn (ASGI server)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
