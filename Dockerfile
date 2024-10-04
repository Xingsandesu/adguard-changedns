FROM ubuntu:20.04
LABEL maintainer="bncfbb <bncfbb@163.com>"
ARG TZ=Asia/Shanghai
ARG DEBIAN_FRONTEND="noninteractive"
COPY ./* /app/
WORKDIR /app/
RUN apt-get update \
    && apt-get install python3 python3-pip tzdata -y \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install -r requirements.txt --no-cache-dir \
    && chmod +x ./main.py \
    && echo "${TZ}" > /etc/timezone \
    && ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime
ENTRYPOINT ["/app/main.py", "-c", "/config/config.yaml"]
