DC = docker compose run --rm dotnet

.PHONY: build restore test format format-check example example-request shell

# Build the dev/test image
build:
	docker compose build

# Restore NuGet dependencies
restore:
	$(DC) dotnet restore

# Run the xUnit test suite (implicitly restores + builds; warnings are errors)
test:
	$(DC) dotnet test

# Auto-fix code style
format:
	$(DC) dotnet format

# Check code style (fails if any file would change)
format-check:
	$(DC) dotnet format --verify-no-changes

# Print a signed SA token: make example KEY=./sa-key.pem KID=<kid> [LIFETIME=3600]
# --verbosity quiet keeps MSBuild's build output off stdout, so the token is all that is printed.
example:
	$(DC) dotnet run --project examples/GenerateToken --verbosity quiet -- "$(KEY)" "$(KID)" $(LIFETIME)

# Call a DMS endpoint with a signed SA token: make example-request KEY=./sa-key.pem KID=<kid> URL=<url>
example-request:
	$(DC) dotnet run --project examples/CallDmsApi --verbosity quiet -- "$(KEY)" "$(KID)" "$(URL)"

# Open a shell in the container
shell:
	$(DC) sh
