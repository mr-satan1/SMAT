FROM ubuntu:14.04
MAINTAINER mr-satan
ENV YARA_VERSION 3.5.0
RUN apt-get update -y
RUN apt-get install -y python-pip \
                       python-dev \
                       build-essential \
                       libssl-dev \
                       git \
                       libtool \
                       autoconf \
                       automake \
                       sqlite3 \
                       libmagic-dev
WORKDIR /tmp
RUN echo "Install Yara from source..." \
&& git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git \
&& cd /tmp/yara \
&& ./bootstrap.sh \
&& sync \
&& ./configure --enable-magic \
               --with-crypto \

&& make \
&& make install \
&& echo "Installing yara-python" \
&& git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara-python \
&& cd yara-python \
&& python setup.py build --dynamic-linking \
&& python setup.py install \
&& echo "Make test_rule..." \
&& mkdir /rules \
&& echo "rule dummy { condition: true }" > /rules/test_rule \
&& rm -rf /tmp/* \
&& echo "/usr/local/lib" >> /etc/ld.so.conf \
&& ldconfig



COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
