# FROM prefecthq/prefect:0.14.5-python3.7 as base_image
FROM python:3.8 as base_image

# Install pip
RUN python -m pip install --upgrade pip
ENV BASE_DIR=/app
# create a venv
RUN python3 -m pip install --user virtualenv
# this removes the need to do source activate, command source is not availabe by default
# see: https://pythonspeed.com/articles/activate-virtualenv-dockerfile/
ENV VIRTUAL_ENV=/opt/dev
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN apt-get update
RUN apt-get install ffmpeg libsm6 libxext6  -y
# needed to get rid of ImportError: libtk8.6.so
RUN apt-get install tk -y
RUN apt-get install nano
RUN pip3 --no-cache-dir install --upgrade awscli
RUN mkdir -p $BASE_DIR
COPY requirements.txt $BASE_DIR/requirements.txt
WORKDIR $BASE_DIR
RUN pip install -r requirements.txt
COPY vault_k8s_auth.py/ $BASE_DIR/vault_k8s_auth.py