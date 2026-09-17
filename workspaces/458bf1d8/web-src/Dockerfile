FROM node:latest

RUN apt-get update && \
    apt-get install -y python3 python3-pip supervisor chromium

RUN pip3 install flask requests git+https://github.com/trentm/python-markdown2 bleach --break-system-packages

RUN useradd -u 1001 botuser && \
    mkdir -p /home/botuser && \
    chown -R botuser:botuser /home/botuser

# Bot things
WORKDIR /bot
COPY bot/package.json .
COPY bot/package-lock.json .

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome

RUN npm install


COPY bot/ /bot

RUN chown -R botuser:botuser /bot


# Chall things
WORKDIR /app
COPY src/ /app

RUN chown -R botuser:botuser /app

# supervisor
COPY config/supervisord.conf /etc/supervisord.conf

RUN useradd -u 1002 appuser && \
    chown -R appuser:appuser /app

USER botuser

ENTRYPOINT [ "/usr/bin/supervisord", "-c", "/etc/supervisord.conf" ]
