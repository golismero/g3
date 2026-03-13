# Golismero3 -- The Pentesting Swiss Army Knife
![Golismero3 Logo](misc/logo_transparent_small.png "Golismero3 Logo")

## What is Golismero3?
Golismero is an open source framework for integrating security testing tools. It's currently geared towards web and network security, but it can easily be expanded to other kinds of scans.

The most interesting features of the framework are:
* Developed in Golang.
* Easy to integrate tools with.
* Completely dockerized by design.
* Can both run tools and collect the output files of previous runs.
* Can be used locally from the command line, following a Unix philosophy.
* Can be used remotely as a scan service, using an HTTP API.

You can find the list of currently supported tools in the [plugins](../blob/master/plugins) folder.

## What will be the next features?

The planned future features of Golismero3 are:
* Integration with Metasploit, Nessus, Burp Suite Pro, and many other tools.
* Web UI. We all know true h4xx0rs only use the console, but sometimes drag&drop does come in handy. ;)
* Export results in PDF and MS Word format, to keep the boss happy.
* And more plugins of course!

## Basic usage
There are two modes of operation: local and remote. When running locally, you can use the power of your favorite shell scripting language to integrate tools however you see fit. For example, the following command will run nmap against 192.168.1.1, then run testssl against any open ports that nmap detected are using SSL/TLS, then generate a report in Markdown format:

```
g3 target 192.168.1.1 | g3 run nmap | g3 run testssl | g3 report -o report.md
```

All of the integrated tools are available in this mode, and you can also import the output files of those tools (if you prefer to run them yourself). What the g3 command really does is provide a JSON common input/output format for all of the integrated tools, which looks like this:

```
$ g3 target 192.168.1.1 --beautify
[
  {
    "_end": 1686498189,
    "_fp": [
      "g3 target 192.168.1.1"
    ],
    "_start": 1686498189,
    "_tool": "g3",
    "_type": "host",
    "ipv4": "192.168.1.1"
  }
]
```

For more details, check out the g3 command help:
```
$ g3 --help
Usage: g3 <command>

Golismero3 - The Pentesting Swiss Army Knife

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  target    Prepare a list of targets.
  tools     List the available tools.
  import    Load the output of a tool.
  run       Run a tool.
  merge     Launch issue merger plugins.
  join      Join multiple G3 output files into one.
  filter    Filter the input using a logical condition.
  report    Produce a Markdown vulnerability report.

Run "g3 <command> --help" for more information on a command.
```

## Advanced usage
The local mode is fine if you're working by yourself and are doing simple tests, but what happens if you have an entire team and you all want to launch your scans from a server? Remote mode has you covered. There is a simple command line tool that you can use to talk to a Golismero3 server:

```
$ g3cli --help
Usage: g3cli <command>

Golismero3 - The Pentesting Swiss Army Knife

Flags:
  -h, --help                Show context-sensitive help.
  -u, --username="admin"    Username.
  -p, --password="admin"    Password.
  -q, --quiet               Suppress stderr output except on fatal errors.

Commands:
  scan        Start a new scan or re-start an existing stopped scan.
  progress    Show the progress of each running scan in real time.
  logs        Show the execution logs of a scan.
  ls          Show the list of all scans.
  ps          Show the list of currently running scans.
  cancel      Cancel a running scan.
  report      Produce a Markdown report for a completed scan.
  export      Export the JSON data for a scan.
  tools       Show the list of tools supported by the server.
  rm          Delete all information of a scan.

Run "g3cli <command> --help" for more information on a command.
```

The server expects your scan to be specified as scripts, with an extremely simple syntax, which you will immediately recognize is similar to the local mode usage:

```
# Specify targets using the "target" command.
target 192.168.1.1

# Use the tool names as commands and pipe them
# just like you would with the command line.
nmap | testssl
```

A series of environment variables need to be set for this and other commands to work. You can find all of these in the `.env` file that comes with Golismero3. The most crucial ones right now are `G3_API_BASEURL` and `G3_API_WEBSOCKET`, which point to the Golismero3 server you want to connect to.

```
G3_API_BASEURL=http://localhost:8080/g3api
G3_API_WEBSOCKET=ws://localhost:8080/g3api/ws
```

Now you can launch a scan! Use the ps and logs commands to see how it's doing.

```
$ scanid=$(g3cli scan -i samples/example.script)
$ g3cli ps

               SCAN ID                  STATUS    PROGRESS               MESSAGE
-------------------------------------- --------- ---------- ----------------------------------
 b9059ae7-2b3b-4ac7-8903-77f06a351e21   RUNNING     20%      Running... (2/10 steps complete)
```

If you want to stop a scan, just use the cancel command:

```
$ g3cli cancel $scanid
```

And you can produce a Markdown report as well, even if the scan did not finish, using the report command:

```
$ g3cli report $scanid -o report.md
Errors were encountered when generating the report:
---------------------------------------------------
Could not find a finished report object in Redis, this could mean the scan has not finished yet.

$ ls -l report.md
-rw-r--r-- 1 ubuntu ubuntu 21815 jun 11 17:59 report.md
```

## Local install
If you just want to try out the tool in your laptop, here's the tutorial you need to follow. This assumes you have Debian, Ubuntu, Kali, or similar.

First, you'll need to install Docker. **Do not use the version that comes with your OS**, follow the official instructions instead:

* https://docs.docker.com/engine/install/

Note that after installing Docker for the first time, you may have restart for all required configuration changes to be applied.

Next, you'll need to install Python and Go, plus some more dependencies:

```
sudo apt install -y git make python3 python3-dev python3-pip
sudo snap install go --classic
```

Now you can download the source code, compile the binaries and build the Docker images locally:

```
git clone https://github.com/golismero/golismero3
cd golismero3
make all
```

If all went well, you can also install some handy symbolic links for ease of use:

```
make all
sudo make install
```

This will only allow you to use the `g3` command. If you want to try out `g3cli`, there's a ready-made `docker-compose.yml` file that you can just launch for a localhost-only demo server:

```
docker compose up
```

Once the demo server is up, you can use the `g3cli` command in a different terminal to connect to it. To shut down the server, go back to the original terminal and hit Control+C.

## Server deployment
The provided `.env` and `docker-compose.yml` files give you a good idea of how to deploy a Golismero3 server. However, these files are only provided for testing, and should not be used in production!

Now we will review what a simple deployment might look like. This is not meant to be a guide to follow step by step, but just a bird's eye view of what you may have to do, and you will need to adjust it to your own situation.

Installation begins exactly like the [previous instructions](#local-install).

After doing that, review the [.env](../blob/master/.env) and [docker-compose.yml](../blob/master/docker-compose.yml) files, since the one that comes by default is meant to be run locally to try out the tool. These files have comments that explain what everything does. The most crucial ones to look at are the various passwords for the services and the JWT secret key, as well as binding the API service to `0.0.0.0` instead of `127.0.0.1` and closing all other ports.

The default `docker-compose.yml` only allows running two scans and four tools at a time, which is fine for a quick spin when trying on your laptop but may be too little for a proper server. Try adding extra services to support more concurrency, as specified in the comments.

Note that Golismero3 does not by itself support SSL, so you will need to put a reverse proxy between the API and the clients, such as for example [lscr.io/linuxserver/swag](lscr.io/linuxserver/swag).

<details>
<summary>Example docker-compose.yml file</summary>

This is what an example `docker-compose.yml` file might look like in production, allowing 4 consecutive scans, 4 concurrent nmap scans, and 12 concurrent executions for the rest of the supported tools:

```
version: '3.6'

networks:
  g3net:
    name: g3net

services:
  swag:
    image: lscr.io/linuxserver/swag
    depends_on:
      - g3api
    cap_add:
      - NET_ADMIN
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/London
      - URL=putyourhostnamehere.com
      - SUBDOMAINS=g3
      - VALIDATION=http
      - ONLY_SUBDOMAINS=false
      - EXTRA_DOMAINS=
      - STAGING=false
    networks:
      - g3net
    volumes:
      - ./volumes/swag:/config
    ports:
      - "443:443"
      - "80:80"
    restart: unless-stopped

  mongo:
    image: mongo:4.4.6
    restart: unless-stopped
    networks:
      - g3net
    volumes:
      - ./volumes/mongo:/data/db
    environment:
      MONGO_INITDB_ROOT_USERNAME: "${MONGO_USERNAME}"
      MONGO_INITDB_ROOT_PASSWORD: "${MONGO_PASSWORD}"

  mosquitto:
    image: eclipse-mosquitto
    restart: unless-stopped
    networks:
      - g3net
    volumes:
      - ./volumes/mosquitto/config:/mosquitto/config/
      - ./volumes/mosquitto/log:/mosquitto/log/
      - ./volumes/mosquitto/data:/mosquitto/data/

  mariadb:
    image: mariadb
    restart: unless-stopped
    networks:
      - g3net
    volumes:
      - ./volumes/mariadb/data:/var/lib/mysql
      - ./volumes/mariadb/initdb.d:/docker-entrypoint-initdb.d:ro
    environment:
      MYSQL_ROOT_PASSWORD: "${SQL_ROOT_PASSWORD}"
      MYSQL_DATABASE: "${SQL_DATABASE}"
      MYSQL_USER: "${SQL_USERNAME}"
      MYSQL_PASSWORD: "${SQL_PASSWORD}"

  redis:
    image: redis:latest
    command: redis-server --port ${REDIS_PORT} --requirepass ${REDIS_PASSWORD}
    restart: unless-stopped
    networks:
      - g3net
    volumes:
      - ./volumes/redis:/data

  g3api:
    image: golismero3/g3bin
    entrypoint: /bin/g3api
    restart: unless-stopped
    depends_on:
      - mariadb
      - mongo
      - mosquitto
      - redis
    networks:
      - g3net
    volumes:
      - ./config:/app/config
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - G3HOME=/app
      - MONGO_URL=mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/
      - SQL_DRIVER=mysql
      - SQL_DSN=${SQL_USERNAME}:${SQL_PASSWORD}@tcp(mariadb:3306)/${SQL_DATABASE}
      - MQTT_URL=mqtt://${MQTT_USERNAME}:${MQTT_PASSWORD}@mosquitto:1883/
      - REDIS_HOST=redis
      - REDIS_PORT
      - REDIS_PASSWORD
      - G3_JWT_SECRET
      - G3_JWT_LIFETIME
      - G3_WS_ADDR=0.0.0.0
      - G3_WS_PORT
      - G3_WS_BUFFER
      - G3_LOG_LEVEL

  g3scanner1:
    image: golismero3/g3bin
    entrypoint: /bin/g3scanner
    restart: unless-stopped
    depends_on:
      - mariadb
      - mongo
      - mosquitto
      - redis
    networks:
      - g3net
    volumes:
      - ./config:/app/config
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - G3HOME=/app
      - MONGO_URL=mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/
      - SQL_DRIVER=mysql
      - SQL_DSN=${SQL_USERNAME}:${SQL_PASSWORD}@tcp(mariadb:3306)/${SQL_DATABASE}
      - MQTT_URL=mqtt://${MQTT_USERNAME}:${MQTT_PASSWORD}@mosquitto:1883/
      - REDIS_HOST=redis
      - REDIS_PORT
      - REDIS_PASSWORD
      - G3_SCANNER_PARALLEL_MODE
      - G3_SCANNER_MAX_PIPELINES
      - G3_SCANNER_MAX_DEPTH
      - G3_LOG_LEVEL

  # ...insert 3 more of these...

  g3worker1:
    image: golismero3/g3bin
    entrypoint: /bin/g3worker
    restart: unless-stopped
    depends_on:
    - mariadb
    - mongo
    - mosquitto
    networks:
    - g3net
    volumes:
    - ./config:/app/config
    - /var/run/docker.sock:/var/run/docker.sock
    environment:
    - G3HOME=/app
    - MONGO_URL=mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/
    - SQL_DRIVER=mysql
    - SQL_DSN=${SQL_USERNAME}:${SQL_PASSWORD}@tcp(mariadb:3306)/${SQL_DATABASE}
    - MQTT_URL=mqtt://${MQTT_USERNAME}:${MQTT_PASSWORD}@mosquitto:1883/
    - G3_WORKER_PLUGINS=nmap
    - G3_HOLD_CANCEL
    - G3_LOG_LEVEL

  # ...insert 3 more of these...

  g3worker5:
    image: golismero3/g3bin
    entrypoint: /bin/g3worker
    restart: unless-stopped
    depends_on:
    - mariadb
    - mongo
    - mosquitto
    networks:
    - g3net
    volumes:
    - ./config:/app/config
    - /var/run/docker.sock:/var/run/docker.sock
    environment:
    - G3HOME=/app
    - MONGO_URL=mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/
    - SQL_DRIVER=mysql
    - SQL_DSN=${SQL_USERNAME}:${SQL_PASSWORD}@tcp(mariadb:3306)/${SQL_DATABASE}
    - MQTT_URL=mqtt://${MQTT_USERNAME}:${MQTT_PASSWORD}@mosquitto:1883/
    - G3_WORKER_PLUGINS=!nmap
    - G3_HOLD_CANCEL
    - G3_LOG_LEVEL

  # ...insert 11 more of these...
```

</details>

Finally, you will want to change the default credentials, which are admin:admin for the test deployment. You can find the database initialization script with the hashed credentials at [volumes/mariadb/initdb.d/create_tables.sql](../blob/master/volumes/mariadb/initdb.d/create_tables.sql). The credentials are protected using bcrypt, but you can use any online service to come up with your own values, for example: [https://bcrypt.online/](https://bcrypt.online/).

Now you can start the services using Docker Compose. Note the -d at the end, this instructs Docker to run all services in the background.

```
docker compose up -d
```

Although in this example we deployed all of the services to be running on the same machine, this is not at all required. You can just have the databases or even the Golismero3 specific services run anywhere else. However, again, there is no built-in SSL support, so you'd have to provide your own secure tunneling. Doing so is well beyond the scope of this tutorial.
