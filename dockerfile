FROM python:3.7

# The enviroment variable ensures that the python output is set straight
# to the terminal with out buffering it first
ENV PYTHONUNBUFFERED 1

# create root directory for our project in the container
RUN mkdir /webhook

# Copy the current directory contents into the container at /music_service
ADD . /webhook/

# Set the working directory to /music_service
WORKDIR /webhook

RUN pip install -r requirements.txt

EXPOSE 5656
