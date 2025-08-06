# syntax=docker/dockerfile:1

# Stage 1: Build stage
# FROM python:3.7 as builder

FROM nvidia/cuda:11.7.1-cudnn8-devel-ubuntu20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt update
RUN apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev wget libbz2-dev
RUN apt-get install -y software-properties-common

RUN add-apt-repository -y ppa:deadsnakes/ppa
RUN apt install -y python3.7
RUN apt install -y python3.7-distutils

RUN apt install -y git

# Make python 3.7 the default
RUN echo "alias python=python3.7" >> ~/.bashrc
RUN export PATH=${PATH}:/usr/bin/python3.7
RUN /bin/bash -c "source ~/.bashrc"

# Add 3.7 to the available alternatives
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.7 1

# Set python3.7 as the default python
RUN update-alternatives --set python /usr/bin/python3.7

# Install pip
RUN apt install python3-pip -y
RUN python -m pip install --upgrade pip

WORKDIR /app

COPY ./requirements.txt .
COPY ./DB ./DB

RUN pip3 install -r requirements.txt

# Install radare2
RUN git clone https://github.com/radareorg/radare2

RUN radare2/sys/install.sh

# Install LLVM-12
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 12
