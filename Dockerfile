FROM python:3.11.7-slim-bullseye AS venv_image
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.11.7-slim-bullseye
LABEL maintainer="bncfbb/Fushinn <https://github.com/Xingsandesu/adguard-changedns/>"
ARG TZ=Asia/Shanghai
ARG DEBIAN_FRONTEND="noninteractive"
ENV PATH=/root/.local/bin:$PATH
COPY --from=venv_image /root/.local /root/.local
WORKDIR /app/
COPY . /app/
RUN apt-get update \
    && apt-get install tzdata -y \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x ./main.py \
    && echo "${TZ}" > /etc/timezone \
    && ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime
ENTRYPOINT ["/app/main.py", "-c", "/config/config.yaml"]
