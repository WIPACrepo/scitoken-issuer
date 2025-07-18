FROM python:3.13

RUN groupadd -g 1000 app && useradd -m -g 1000 -u 1000 app

RUN mkdir /mnt/data

RUN mkdir /app
WORKDIR /app

COPY src /app/src
COPY pyproject.toml /app/pyproject.toml

RUN chown -R app:app /app

USER app

ENV VIRTUAL_ENV=/app/venv

RUN python3.13 -m venv $VIRTUAL_ENV

ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN --mount=source=.git,target=.git,type=bind pip install -e .

CMD ["python", "-m", "scitoken_issuer"]
