# Qumulo SMB Lock Manager - Docker Deployment

## Installation

**These directions assume your host has network access to `hub.docker.com`**

- Download or clone all files in the DOCKER directory
- Edit `/app/async_main.conf` with your information
- Edit `dockerfile` and `docker-compose.yml` if you'd like to use a different TCP port than 4000
- `cd` into the `DOCKER` directory and build the application with `docker-compose build`
- Run the application with `docker-compose up` add the option `--detach` if you'd like to run it in the background

**Please note that currently only basic authentication for single web UI user is provided**