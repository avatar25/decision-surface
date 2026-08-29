package gateway

import rego.v1

default allow := false

# --- identity -------------------------------------------------------------

is_admin if input.user.role == "admin"

is_editor if input.user.role == "editor"

verified_human if {
	input.user.verified
	input.user.age >= 18
}

sufficient_clearance if input.user.clearance >= 3

# --- request shape --------------------------------------------------------

read_method if input.method in {"GET", "HEAD"}

write_method if input.method in {"POST", "PUT", "PATCH"}

api_path if startswith(input.path, "/api")

admin_path if startswith(input.path, "/admin")

under_rate_limit if input.request.rate < 100

# --- token ----------------------------------------------------------------

token_valid if {
	not input.token.expired
	input.token.issuer == "internal"
}

# --- resource -------------------------------------------------------------

public_resource if input.resource.classification == "public"

internal_resource if input.resource.classification == "internal"

# --- decision -------------------------------------------------------------

allow if {
	is_admin
	token_valid
}

allow if {
	is_editor
	write_method
	api_path
	token_valid
	under_rate_limit
}

allow if {
	read_method
	public_resource
}

allow if {
	read_method
	internal_resource
	verified_human
	token_valid
}

allow if {
	api_path
	read_method
	sufficient_clearance
	not admin_path
}
