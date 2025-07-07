package main

import rego.v1

deny contains msg if {
    lower(input[i].Cmd) == "add"
    msg := "Use COPY instead of ADD command in Dockerfile for better security and predictability"
}

deny contains msg if {
    lower(input[i].Cmd) == "from"
    val := input[i].Value[0]
    endswith(val, ":latest")
    msg := "Do not use 'latest' tag for base images - specify explicit version tags"
}

deny contains msg if {
    lower(input[i].Cmd) == "from"
    val := input[i].Value[0]
    not contains(val, ":")
    msg := "Do not use implicit 'latest' tag for base images - specify explicit version tags"
}

deny contains msg if {
    not has_user_command
    msg := "Container should not run as root user - add USER instruction"
}

deny contains msg if {
    lower(input[i].Cmd) == "user"
    val := input[i].Value[0]
    val == "root"
    msg := "Container should not run as root user"
}

deny contains msg if {
    lower(input[i].Cmd) == "user"
    val := input[i].Value[0]
    val == "0"
    msg := "Container should not run as root user (UID 0)"
}

has_user_command if {
    lower(input[_].Cmd) == "user"
}