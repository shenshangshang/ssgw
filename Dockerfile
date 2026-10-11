FROM node:22-slim
RUN apt-get update -qq && apt-get install -y -qq poppler-utils && rm -rf /var/lib/apt/lists/*
