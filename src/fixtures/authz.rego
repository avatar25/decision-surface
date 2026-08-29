package authz

import rego.v1

default allow := false

allow if {
    input.role == "admin"
}

allow if {
    input.role == "editor"
    input.action in {"read", "write"}
}

allow if {
    input.action == "read"
    not input.resource.confidential
}
