FROM python:3.12-alpine AS venv_image
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.12-alpine
LABEL maintainer="bncfbb/Fushinn <https://github.com/Xingsandesu/adguard-changedns/>"
ARG TZ=Asia/Shanghai
ENV PATH=/root/.local/bin:$PATH
COPY --from=venv_image /root/.local /root/.local
WORKDIR /app/
COPY . /app/
RUN apk add --no-cache tzdata \
    && chmod +x ./main.py \
    && cp /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TZ}" > /etc/timezone \
    && apk del tzdata
ENTRYPOINT ["/app/main.py", "-c", "/config/config.yaml"]