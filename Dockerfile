# ---- Build Stage ----
# Use a base image with Maven and JDK to build the application
FROM maven:3.9-eclipse-temurin-21 AS build 

# Set the working directory inside the build stage
WORKDIR /workspace/app

# Copy the Maven POM file first to leverage Docker layer caching
COPY pom.xml .

# Download Maven dependencies (this layer is cached if pom.xml doesn't change)
# Using dependency:go-offline avoids downloading during the package phase if possible
RUN mvn dependency:go-offline -B

# Copy the rest of the application source code
COPY src ./src

# Package the application, skipping tests (they should be run separately)
# Ensure the finalName in pom.xml results in a predictable JAR name, or adjust the COPY below.
# Default is usually ${project.artifactId}-${project.version}.jar
RUN mvn package -DskipTests

# Example: If pom.xml defines <finalName>app</finalName>, the JAR will be app.jar
# If not, it will be something like target/lite-vault-0.5.0.jar

# ---- Runtime Stage ----
# Use a minimal JRE base image for the final runtime container
FROM openjdk:21-jdk-slim

# Define build arguments that can be passed during build time
# Defaulting to the JAR name based on pom.xml artifactId and version
ARG JAR_FILE_PATH=/workspace/app/target/lite-vault-0.4.0.jar

# Set the working directory for the runtime stage
WORKDIR /app

# Create a non-root user and group
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Install curl for HEALTHCHECK and clean up apt cache
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy only the packaged JAR from the build stage to the runtime stage
# Renaming it to app.jar for consistency
COPY --from=build ${JAR_FILE_PATH} app.jar
RUN mkdir /app/lite-vault-data

# Change ownership of the application directory and JAR file to the non-root user
# This might be necessary depending on the base image and permissions
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Expose the port the application runs on (default 8080)
EXPOSE 8443

# Environment variable for JVM options. Can be overridden at runtime.
# -XX:+UseContainerSupport: Make JVM aware of container memory limits
# -XX:MaxRAMPercentage=80.0: Use 80% of container memory for heap (adjust as needed)
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=80.0"

# Define the health check using the root endpoint
# --interval: How often to run the check
# --timeout: Max time to wait for the check command
# --start-period: Grace period after container start before failures count
# --retries: Number of consecutive failures to mark as unhealthy
# CMD: The command to run
#   curl: Tool to make HTTP request#   --fail (-f): Return error on server errors (4xx, 5xx)
#   --insecure (-k): Ignore SSL certificate validation (useful for self-signed certs)
#   https://localhost:8443/: Target URL (localhost because check runs inside container)
#   || exit 1: Ensure non-zero exit code if curl fails for other reasons (e.g., connection refused)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl --fail --insecure https://localhost:8443/ || exit 1

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]
