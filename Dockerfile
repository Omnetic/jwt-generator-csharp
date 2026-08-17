# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:8.0

# Quieter, non-interactive CLI for container/CI use.
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

WORKDIR /app

CMD ["dotnet", "--info"]
