ARG  CODE_VERSION=0.3.1-3.7
FROM atom-python:${CODE_VERSION}

LABEL maintainer="richwats@cisco.com"
RUN yum update

RUN yum install git -y

## Build Virtual Environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV FLASK_APP=restServer.py
## ENV FLASK_DEBUG=1
ENV BASE_PATH="/appcenter/Cisco/DCNM_ACLM/aclm_api"
## ENV DCNM_MGMT_VIP=10.67.29.26 ## Set automatically

# Install dependencies:
COPY requirements.txt .

# Override PIP index
COPY pip.conf /etc/

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

## Workaround for broken flask-session
RUN pip install git+https://github.com/rayluo/flask-session.git@0.3.x

# Expose Ports
EXPOSE 5000/tcp

# COPY APP
COPY app /app

# Change Working Directory
WORKDIR /app

# Run Flask
ENTRYPOINT flask run --host=0.0.0.0
