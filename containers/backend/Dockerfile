ARG  CODE_VERSION=0.3.1-3.7
FROM atom-python:${CODE_VERSION}

LABEL maintainer="richwats@cisco.com"
RUN yum update

## Build Virtual Environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV FLASK_APP=restServer.py;
ENV FLASK_DEBUG=1

# Install dependencies:
COPY requirements.txt .

# Override PIP index
COPY pip.conf /etc/

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose Ports
EXPOSE 5000/tcp

# Change Working Directory
WORKDIR /app

# Run the application:
#COPY myapp.py .
#CMD ["python", "myapp.py"]
