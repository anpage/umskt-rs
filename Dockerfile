FROM rust:1.70-alpine as build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . /src
RUN cargo build --release


FROM scratch as output
COPY --from=build /src/target/release/mskey /mskey
ENTRYPOINT ["/mskey"]
