---
layout: post
title: Week 1 - Intro & Simple Docker Orchestration
tags: [year-of-hacking, development]
---
I'm setting out to write a short blog post every week about whatever Cybersecurity or information security related topic I'm working on. There will likely be repeats, and cop-outs where I can't post source code because it's linked to a school assignment, and more than a few weeks that aren't related to security. Hopefully they will be published each Monday for the next year.

I'm hoping by the end of this project, I will have increased my technical expertise in a variety of different fields, and get a decently broad survey of the cybersecurity landscape, as well as better my writing skills and keep a public record of some of the technical feats I've accomplished.
# Docker
Docker is an incredibly widespread and useful technology, packaged with half a dozen enterprise software platforms. It is old, so to my understanding it's being phased out in favor of newer solutions like Podman which don't require root privileges out of the box. Regardless, it still is an immensely useful tool for people working in information security as it allows professionals to work with complicated software setups that don't necessitate a full VM, but could benefit from a custom environment. I've dabbled in docker before for school assignments, using the Kali Linux image before I set up the Kali Linux WSL instance, and using the afl-fuzz image during previous experiments with fuzzing. 

In order to solidify the concept of docker images and container orchestration, I designed a simple project that could benefit from having multiple docker containers. I think it would be interesting to see what gifs people choose to correlate with certain songs. For example the Polish song [Gdzie Jest Bialy Wegorz](https://open.spotify.com/track/40rPqOehcndc4xODWUCfYo?si=efabf09152f9462a) by Cypis has been associated with this gif of a dancing Holstein cow like [this video with 1.5 Million views](https://www.youtube.com/watch?v=Vy8moBcKVIM&ab_channel=skeet), which is peculiar given the vulgar lyrics about drug addiction and withdrawal.
![Polish Cow Meme](https://imgs.search.brave.com/vyhNnOzvLjBSo2fhUGwEU5QacyS_v0cyAWQXgwH9k5g/rs:fit:860:0:0/g:ce/aHR0cHM6Ly9tZWRp/YTEudGVub3IuY29t/L20vX2dmcWZYQVAw/OElBQUFBQy9wb2xp/c2gtY293LWNvdy5n/aWY.gif)
I'm creating a simple website that accesses a user's Spotify account and asks them to submit a tenor link. The idea is to have a sizeable user-generated database of what gifs people most associate with a particular song for use by later projects. This is ultimately pretty attainable, and could serve as a teaching tool for my day job as a web security teacher.
## Docker compose file
```yaml
version: '3.9'
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_ROOT_PASSWORD: ${POSTGRES_ROOT_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - db_data:/var/lib/mysql
      - ./queries/init/init.sql:/docker-entrypoint-initdb.d/init.sql
  backend:
    image: "node:20"
    user: "node"
    working_dir: /app
    depends_on:
      - db
    environment:
      NODE_ENV: dev
      POSTGRES_ROOT_PASSWORD: ${POSTGRES_ROOT_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PORT: ${POSTGRES_PORT}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_ALIAS: ${POSTGRES_ALIAS}
    volumes:
      - ./src/:/app/
    ports:
      - "3000:3000"
    links:
      - "db:database"
    command: "npm start"
volumes:
  db_data:
```
### Interesting features with security implications
It is possible to pass environment variables to docker images using the `environment` tag in a docker compose file. It would be pretty easy for a lazy developer to hardcode in sensitive information into these values, exposing credentials should source code for a deployment be leaked. The more secure and easier to manage method is to create a separate `.env` file defining all the environment variables with the sensitive data. Luckily, the developers of docker recognize this as the best practice, so [official documentation](https://docs.docker.com/compose/environment-variables/set-environment-variables/) list this as the primary method. This is what my `.env` file looks like:
```bash
POSTGRES_ROOT_PASSWORD=xxxxx
POSTGRES_DB=spotify_gif
POSTGRES_USER=spotifygifuser
POSTGRES_PASSWORD=xxxxx

POSTGRES_PORT=5432
POSTGRES_ALIAS=database
```
This doesn't provide a perfectly secure way of storing credentials, but instead changes the necessary attack chain from compromising source code for a particular instance of an application, instead necessitating compromising an application while it's running in production, or accessing whatever escrow the deployment-specific `.env` is stored in.

It is possible to map directories from the host of an image to the file system of the guest image under the `volumes` tag. In my example, I've mapped the contents of `./src/` from the project directory to `/app/` on the image. Developers should take care to make sure no non-essential data is being mounted to the image, so that if an attacker were to somehow gain command line access to an image or execute a path traversal attack, sensitive data wouldn't be leaked. In my setup, I don't use all the values of the `.env`, instead I pass the necessary environment variables through the docker compose file. This means unused environment variables are not exposed to images, protecting them if an image gets compromised.

I'm curious to know if a simple docker compose file can be configured to provide load balancing in the event of a backend crashing, or if that functionality can only come with a container orchestration platform like Red Hat's OpenShift.
### New music I listened to this week
[Somethin' Stupid](https://open.spotify.com/track/4feXcsElKIVsGwkbnTHAfV?si=7bee50b3b1ba48b8) by Frank and Nancy Sinatra
[Un Millón de Primaveras](https://open.spotify.com/track/6j5LtifAnuTjTYvml61yFZ?si=86c27fd0a8764d3b) by Vicente Fernandez
