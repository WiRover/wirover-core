#
# Stage 0: build environment
#

# We are using alpine:edge because it has the gpsd-dev package.  We should
# probably switch to alpine:3.8 when that becomes stable.
FROM alpine:edge as build

# Install dev packages, which include headers and libraries for linking.
RUN apk add --no-cache \
        build-base \
        cmake \
        json-c-dev \
        gpsd-dev \
        libconfig-dev \
        libexecinfo-dev \
        libunwind-dev \
        linux-headers \
        openssl-dev

# Make a link so that the json-c library appears where we expect it.
RUN ln -s json-c /usr/include/json && \
    ln -s libjson-c.so /usr/lib/libjson.so

# Copy source and build.
WORKDIR /root
COPY src /root/src
RUN mkdir build && \
    cd build && \
    cmake ../src && \
    make wigateway

# Modify the configuration file to run in a containerized environment.
RUN sed "/interface = \"eth0\"/d" -i build/wigateway/wigateway.conf


#
# Stage 1: runtime environment
#

# Start with the same base image as the build environment to make sure
# we get the same versions of libraries that we built against.
FROM alpine:edge

# We only need a smaller set of packages for the runtime environment.  This
# separation between the build and runtime stages helps keep the resulting
# image small.
RUN apk add --no-cache \
        json-c \
        gpsd-dev \
        libconfig \
        libexecinfo \
        libunwind \
        openssl \
        openssl-dev

# Copy our files into the runtime environment.
COPY scripts/wirover_wrapper.sh /usr/bin/wirover_wrapper.sh
COPY src/version.json /var/lib/wirover/wigateway_version
COPY --from=build /root/build/wigateway/wigateway /usr/bin/wigateway
COPY --from=build /root/build/wigateway/wigateway.conf /etc/wigateway.conf

# Start wigateway with the wrapper script to make sure certain files are
# created at initialization. Most importantly, we need to generate a unique
# private key for each instance.
CMD ["/usr/bin/wirover_wrapper.sh", "/usr/bin/wigateway"]
