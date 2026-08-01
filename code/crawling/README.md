# Scan & ScanCTR CLI Documentation


## Installation
```bash
# Dependencies
apt-get install sqlite3

# Install the CLI tool
pip install scanctr (Recommended `cd scanctr` then `pip install . -e` )
```

## Basic Usage
```bash
scanctr [COMMAND] [OPTIONS]
```

## Available Commands

### `deploy`
Deploy the scanning tool using docker-compose with build option.

```bash
scanctr deploy
```
This command will:
- Locate or prompt for your docker-compose.yml file
- Build and start all defined services
- Create required containers in detached mode

### `demolish`
Tear down the entire deployment and wipe the SQLite queue database.

```bash
scanctr demolish
```
This command will:
- Ask for confirmation before proceeding
- Stop and remove all containers defined in docker-compose.yml
- Remove networks created by docker-compose
- Delete the SQLite queue database file

### `queues`
Display information about all Redis queues used by the system.

```bash
scanctr queues
```
This command shows:
- Task and complete queue names
- Number of pending and completed jobs
- Memory usage for each queue
- Active scan IDs in the queues

### `nodes`
Show the status of all Docker containers.

```bash
scanctr nodes
```
Displays:
- Container IDs
- Images
- Command
- Created time
- Status
- Ports
- Names

### `submit`
Submit a scan request for multiple domains from a file.

```bash
scanctr submit --file domains.txt
```
The file should contain one domain per line.

### `scale`
Scale a specific service to a desired number of replicas.

```bash
scanctr scale SERVICE_NAME REPLICAS
```
Example:
```bash
scanctr scale scan-node 30
```
This scales the "scan-node" service to 30 replicas.

### `wipecache`
Remove the stored configuration file.

```bash
scanctr wipecache
```
This forces the tool to prompt for the docker-compose.yml path on next use.

### `dumpqueue`
Dump the contents of a Redis queue to a local file.

```bash
scanctr dumpqueue QUEUE_NAME --output output.txt
```
If no output file is specified, the default will be `QUEUE_NAME_dump.txt`.

### `deletequeue`
Delete a specific Redis queue and remove its records from SQLite.

```bash
scanctr deletequeue QUEUE_NAME
```

### `wiperedis`
Completely wipe the Redis database and clear SQLite queue records.

```bash
scanctr wiperedis
```

### `help`
Display help information with the ScanCTR banner.

```bash
scanctr help
```

## Configuration
The tool stores your docker-compose.yml path in:
```
~/.scanctrconfig/config.txt
```


## Requirements
- Docker and Docker Compose  
- Python 3.10+  
- sqlite3 `apt-get install sqlite3`
- Redis will forward port 6379 to the local machine, allowing the CLI to connect. If you use a different port, update the Docker Compose configuration before deployment.  
- It is recommended to set permissions for `~/.scanctrconfig/` using `chmod 777` to properly handle the SQLite database.

