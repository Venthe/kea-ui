![Docker Image Version](https://img.shields.io/docker/v/venthe/kea-ui?link=https%3A%2F%2Fhub.docker.com%2Fr%2Fventhe%2Fkea-ui)

Docker image: [here](https://hub.docker.com/r/venthe/kea-ui)

# WARNING: Initial commit is an agentic, almost one-shot. It should NEVER BE USED in ANY capacity

without scrutiny.

## Description

I've needed a small UI for my own airgapped router without the heavy requirements of Stork.

The lightweight Kea UI is available at `http://localhost:8000/` after starting the stack:

```bash
podman compose up -d --build kea-ui kea-dhcp4
```

The configuration is made specifically so I can test the isolated DHCP network without interfering with the L2.

## Capabilities

- DHCP reservations
- DHCP lease revocations
- Socket status
- Login (Absolutely untested - it can be secure, but it can just as well be a dud)

## Usage

### DHCP

Run this only from an isolated test interface or dedicated test container. It requests a lease and exits if no lease is received:

```sh
podman compose exec -it network-multitool udhcpc -i eth1 -R -n -q -x hostname:test-client
```

The current `192.168.50.0/24` Compose network is statically configured, while Kea serves `192.168.0.0/24`; this DHCP test is expected to fail until those networks are aligned.

## Notes on the LLM

I'm surprised that it pinned the requirements, though they are out of date. I absolutely don't understand why I need to mount directories from the original container (except for the socket) but that is not a problem in my case. The abstractions are... Bad.

Thing was generated with 5.6 SOL, and manual work concentrated around the container ecosystem