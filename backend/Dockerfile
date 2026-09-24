FROM python:3.12-slim

WORKDIR /srv

# Install dependencies first (better layer caching)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY backend/app ./app

ENV PYTHONPATH=/srv \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Tables are created idempotently on startup (see app/main.py lifespan);
# demo users + scenarios seed when SEED_DEMO_USERS=true.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
