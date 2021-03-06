WiRover Core
===================

WiRover is an advanced networking solution that provides robust,
high-speed Internet connectivity to vehicles. WiRover was developed as
a research project at the University of Wisconsin-Madison.

The WiRover system is capable of improving the performance of
vehicle-to-Internet applications by connecting to multiple different
wireless network providers simultaneously. This improves the system's
network performance by both increasing the bandwidth available to the
system as well as increasing network diversity. Network diversity in turn
increases the chances that the system will have Internet connectivity
from at least one network provider when there may not be network coverage
from other providers.

Introduction
===================

This is a user-level implementation of WiRover. The WiRover architecture
comprises two main components --- the gateway and the controller. It also
includes a root server that handles mapping gateways to controllers in
the case of large-scale multi-controller deployments.

The mobile platform with one or more managed interfaces is the gateway.
Typically, the gateway is a mobile WiFi access point with multiple
cellular interfaces. It is the access point for one ore more devices
that require an Internet connection, hence the name gateway.

The other component, the controller, is a tunnel endpoint for the
traffic sent through the gateway.  Tunneling is used to implement
reliable handover and performance enhancements. Typically, a controller
will reside in a fixed location with a well-provisioned network and will
provide service to many gateways.

Source Code
===================

    src/wiroot
    src/wigateway
    src/wicontroller
    src/common

The source code is divided into several directories.  The wi*
subdirectories are specific to their respective components. The
common subdirectory contains some shared code and header files.

Quick Start
===================

The quickest way to get started is using [docker-compose](https://docs.docker.com/compose/).

For the controller, all that is required is a Linux server with Docker
and Docker Compose installed and the docker-compose.yml file from this
project.  The controller should have a public IP address that will be
reachable by the gateways.

```bash
wget https://raw.githubusercontent.com/WiRover/wirover-core/master/docker-compose.yml
```

Start the controller software using:

```bash
docker-compose up -d
```

In order for the controller to proxy traffic from the gateways, we
also need to enable packet forwarding and NAT.

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -s 172.16.0.0/12 -j MASQUERADE
```

For the gateways, we recommend using [Ubuntu Core](https://www.ubuntu.com/core),
which is a lightweight version of Ubuntu with transactional updates.

If using Ubuntu Core, install the gateway software using:

```bash
snap install wigateway
```

Set the address of the controller and root server:

```bash
snap set wigateway wiroot-address=192.0.2.1
```

Other configuration settings, such as network interface priorities can
be found in `/var/snap/wigateway/current/wigateway.conf`.

Give wigateway permission to modify network settings:

```bash
snap connect wigateway:firewall-control
snap connect wigateway:network-control
snap connect wigateway:network-observe
snap connect wigateway:network-setup-control
snap connect wigateway:network-setup-observe
```

Then restart the service:

```bash
snap restart wigateway
```

Alternatively, you can also run the gateway using Docker. Fill in the
WIROVER_WIROOT_ADDRESS environment variable with the address of your
server.

```bash
docker run --detach --name=wigateway --privileged --rm --env "WIROVER_WIROOT_ADDRESS=192.0.2.1" --network=host wirover/wigateway
```

Building
===================

The following commands are used to build the individual Docker images
for wicontroller, wigateway, and wiroot:

```bash
docker build --file src/wicontroller/Dockerfile --tag wirover/wicontroller .
docker build --file src/wigateway/Dockerfile --tag wirover/wigateway .
docker build --file src/wiroot/Dockerfile --tag wirover/wiroot .
```
