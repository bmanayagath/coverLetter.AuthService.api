# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy project files first to leverage layer caching for restore
COPY *.csproj ./
RUN dotnet restore

# Copy remaining sources and publish
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app

COPY --from=build /app ./

EXPOSE 8080

ENTRYPOINT ["dotnet", "coverLetter.AuthService.api.dll"]
