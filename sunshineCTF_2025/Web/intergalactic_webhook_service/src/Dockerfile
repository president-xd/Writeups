FROM python:3.11-slim
WORKDIR /opt/chal

# Install uv and dependencies in one layer for better caching
RUN pip install uv

# Create unprivileged unprivileged user. lol.
RUN groupadd -r unprivileged && \
	useradd -r -g unprivileged \
        -d /home/unprivileged \
        -s /bin/bash \
        unprivileged

# Create directories and set permissions for uv
RUN mkdir -p /home/unprivileged/.cache/uv /home/unprivileged/.local/share/uv && chown -R unprivileged:unprivileged /home/unprivileged/.cache /home/unprivileged/.local

COPY pyproject.toml /opt/chal/pyproject.toml
COPY .python-version /opt/chal/.python-version
COPY uv.lock /opt/chal/uv.lock

# Change ownership of the working directory and switch to unprivileged user
RUN chown -R unprivileged:unprivileged /opt/chal
USER unprivileged
RUN uv sync --locked

# Copy application files
COPY --chown=unprivileged:unprivileged . /opt/chal

RUN chmod +x /opt/chal/docker-entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/opt/chal/docker-entrypoint.sh"]

USER root
RUN rm -f Dockerfile
USER unprivileged
