# Use the minimal Alpine image as the base
FROM gcr.io/distroless/static

# Copy a simple script into the container
COPY test/hello.sh /hello.sh

# Run the script by default
CMD ["/bin/sh", "/hello.sh"]