# Use an official Python runtime as a base image
FROM python:3.11

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install any dependencies specified in requirements.txt
COPY requirements.txt /app/
RUN pip install -r requirements.txt

# Expose port 5000 to access Flask from outside the container
EXPOSE 5000

# Set environment variables for Flask
ENV FLASK_APP=app.py

# Run the Flask application when the container starts
CMD ["flask", "run", "--host=0.0.0.0"]