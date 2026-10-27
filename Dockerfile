FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

COPY pyproject.toml README.md ./
COPY godseye ./godseye
RUN pip install --no-cache-dir -e .

EXPOSE 8000
ENTRYPOINT ["godseye"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
