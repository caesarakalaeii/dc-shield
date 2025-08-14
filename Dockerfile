# Use the official Python image as the base image
FROM python:3.13-slim

# Copy the current directory contents into the container at /app
COPY . /app

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


# Set the working directory in the container
WORKDIR /app
# Run main.py when the container launches
CMD ["python", "main.py"]