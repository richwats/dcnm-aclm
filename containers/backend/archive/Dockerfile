ARG  CODE_VERSION=0.3.1-3.7
FROM atom-python:${CODE_VERSION}

LABEL maintainer="richwats@cisco.com"
RUN yum update

## IUS
RUN yum -y install https://$(rpm -E '%{?centos:centos}%{!?centos:rhel}%{rhel}').iuscommunity.org/ius-release.rpm
RUN yum update
RUN yum -y remove python3
RUN yum -y install python36
RUN yum -y install cmake3 libssh-devel gcc-c++ python-devel python-virtualenvwrapper

## Instal YDK from Cisco
RUN yum -y install https://devhub.cisco.com/artifactory/rpm-ydk/0.8.4/libydk-0.8.4-1.x86_64.rpm

### SETUP PYTHON 2.7 VENV
# ..can't access venv during build
# ..ignore or provide global package access?
#RUN virtualenv --python=python2.7 env;
#RUN source env/bin/activate;
RUN python2 -m pip install --upgrade pip
RUN python2 -m pip install ydk-models-cisco-nx-os
RUN python2 -m pip install ydk-models-openconfig
