ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/api
EXPOSE 8000
CMD ["uvicorn","api.app:app","--host","0.0.0.0","--port","8000","--workers","1"]
