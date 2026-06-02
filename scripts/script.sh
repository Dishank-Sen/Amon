#!/bin/bash

readonly ROOT_PATH="$HOME/.amon"
readonly CONFIG_PATH="$ROOT_PATH/config.yaml"

echo "creating config..."
mkdir -p $ROOT_PATH
touch $CONFIG_PATH

echo "done!"