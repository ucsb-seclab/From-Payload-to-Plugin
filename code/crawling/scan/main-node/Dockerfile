FROM ubuntu:latest

USER root

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-venv \
    redis-tools \
    sqlite3

COPY . /app/

RUN python3 -m venv /opt/venv
RUN /bin/bash -c "source /opt/venv/bin/activate && pip install --upgrade pip && pip install -r /app/requirements.txt"

EXPOSE 8181

ENTRYPOINT ["/bin/bash", "-c", "source /opt/venv/bin/activate && exec \"$@\"", "--"]

CMD ["python3", "main.py"]
