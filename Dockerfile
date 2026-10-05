# One image, one profile per container: iai mcps create <name> --image-name gatehouse --image-tag v1 --port 8766
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
ENV CONFIG=examples/igaming/gatehouse.yaml PROFILE=support-write
EXPOSE 8766
CMD gatehouse "$CONFIG" --profile "$PROFILE" --port 8766
