#
# Stage 0: build environment
#

# We use alpine because it is results in compact Docker images.
FROM alpine:3.7 as build

# Install dev packages, which include headers and libraries for linking.
RUN apk add --no-cache \
        build-base \
        cmake \
        json-c-dev \
        libconfig-dev \
        libexecinfo-dev \
        libunwind-dev \
        linux-headers \
        mariadb-dev \
        libressl-dev

# Make a link so that the json-c library appears where we expect it.
RUN ln -s json-c /usr/include/json && \
    ln -s libjson-c.so /usr/lib/libjson.so

# Copy source and build.
WORKDIR /root
COPY src /root/src
RUN mkdir build && \
    cd build && \
    cmake ../src && \
    make wiroot

# Modify the configuration file to run in a containerized environment.
RUN sed "s/mysql-host = .*/mysql-host = \"db\"/" -i build/wiroot/wiroot.conf && \
    sed "s/mysql-password = .*/mysql-password = \"wirover\"/" -i build/wiroot/wiroot.conf

#
# Stage 1: runtime environment
#

# Start with the same base image as the build environment to make sure
# we get the same versions of libraries that we built against
FROM alpine:3.7

# We only need a smaller set of packages for the runtime environment.  This
# separation between the build and runtime stages helps keep the resulting
# image small.
RUN apk add --no-cache \
        json-c \
        libconfig \
        libexecinfo \
        libunwind \
        mariadb-client-libs \
        openssl

# Copy our files into the runtime environment.
COPY src/version.json /var/lib/wirover/wiroot_version
COPY --from=build /root/build/wiroot/wiroot /usr/bin/wiroot
COPY --from=build /root/build/wiroot/wiroot.conf /etc/wiroot.conf

CMD ["/usr/bin/wiroot"]
