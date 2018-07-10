#!/bin/bash

major=$1
minor=$2
revision=$3

if [ -z "$revision" ]; then
    echo "Usage: $0 <major> <minor> <revision>"
    exit 1
fi

if ! [ -x "$(command -v docker)" ]; then
    echo "docker command not found"
    exit 1
fi

if ! [ -x "$(command -v snapcraft)" ]; then
    echo "snapcraft command not found"
    exit 1
fi

echo "{\"version\": \"$major.$minor.$revision\"}" >src/version.json
for component in wicontroller wigateway wiroot; do
    docker build --no-cache --file src/$component/Dockerfile --tag wirover/$component .
    docker tag wirover/$component wirover/$component:$major.$minor.$revision
    docker tag wirover/$component wirover/$component:$major.$minor
done

sed "s/version: .*/version: $major.$minor.$revision/" -i snap/snapcraft.yaml
snapcraft clean
snapcraft

echo "Next steps:"
for component in wicontroller wigateway wiroot; do
    echo "docker push wirover/$component"
done
for snap in wigateway_$major.$minor.$revision_*.snap; do
    echo "snapcraft push $snap"
done
