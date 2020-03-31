ARG  CODE_VERSION=0.3.1-3.7
FROM atom-python:${CODE_VERSION}

LABEL maintainer="richwats@cisco.com"
RUN yum update

## Build Virtual Environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install dependencies:
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Run the application:
#COPY myapp.py .
#CMD ["python", "myapp.py"]
