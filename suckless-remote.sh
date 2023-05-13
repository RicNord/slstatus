#!/bin/bash

git remote add suckless https://git.suckless.org/slstatus \
    && git checkout -b suckless \
    && git fetch suckless \
    && git branch --set-upstream-to suckless/master
