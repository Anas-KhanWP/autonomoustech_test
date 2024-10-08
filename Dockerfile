# Use an official Python runtime as a parent image
FROM python:3

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container to /app
RUN mkdir /app
WORKDIR /app

# Add the current directory files (on your machine) to the container
COPY . /app

# Install any needed packages specified in requirements.txt
# RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose the port server is running on
# EXPOSE 8000

# Start the server
# CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
