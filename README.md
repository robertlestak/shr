# shr

`shr` is a simple file sharing service. It's useful when you want to share one or more files without relying on a third party service like Dropbox or Google Drive, cannot ensure a stable p2p connection, and cannot use torrents.

## Other Protocols to Consider

Before we dive into how and why to use `shr`, let's first consider some other protocols that might be more appropriate for your use case.

### Cloud Hosting Services (S3, Dropbox, Google Drive, etc.)

If you're looking to share a file with a small group of people, you might consider using a cloud hosting service like Dropbox, Google Drive, or Amazon S3. These services are easy to use, and they're free for small amounts of data. However, they have some drawbacks:

* You have to trust the service provider to not abuse your data.
* You have to trust the service provider to not go out of business.
* You have to trust the service provider to not be hacked.
* You have to trust the service provider to not be sued.
* You have to trust the service provider to not be bought by a company that doesn't share your values.
* You have to trust the service provider to not be bought by a government that doesn't share your values.
* You have to trust the service provider will not be forced to comply with a government that doesn't share your values.
* You have to trust the service provider will not remove your data on their own volition.

### BitTorrent

If you're looking to share a file with a large group of people, you might consider using BitTorrent. BitTorrent is a peer-to-peer protocol that allows you to share files with a large number of people. It's a great protocol, but it has some drawbacks:

* Unless specifically architected to do so, BitTorrent is not a good protocol for sharing files with a small number of people.
* BitTorrent is generally not a good protocol for sharing files with people who are behind a NAT without additional configuration.
* By default, torrents do not have an encryption or authentication layer, which means that you are responsible for data security.
* Once published, a torrent is immutable. If you want to update a file, you have to publish a new torrent. Additionally, the data owner has no way to revoke access to a torrent once it's been published.

### IPFS

If you're looking to share a file with a large group of people, you might consider using IPFS. IPFS is a peer-to-peer protocol that allows you to share files with a large number of people. It's a great protocol, but it has some drawbacks:

* Unless specifically architected to do so, IPFS is not a good protocol for sharing files with a small number of people.
* IPFS is generally not a good protocol for sharing files with people who are behind a NAT without additional configuration.
* By default, IPFS does not have an encryption or authentication layer, which means that you are responsible for data security.
* Once published, a file is immutable. If you want to update a file, you have to publish a new file. Additionally, the data owner has no way to revoke access to a file once it's been published.

### HTTP

If you're looking to share files with N number of users, HTTP is a versatile, simple, and widely supported protocol with countless client integrations. It's a great protocol, but it has some drawbacks:

* HTTP is not a good protocol for sharing files with people who are behind a NAT without additional configuration.
* Generally HTTP requires some infrastructure to be set up before it can be used.
* While HTTP does have an authentication and encryption layer, these require additional configuration and are not enabled by default.

### netcat

Probably one of the most simple protocols for sharing files is netcat. However it has many drawbacks at scale:

* It requires a stable p2p connection between the sender and receiver.
* It requires the sender and receiver to be on the same network, or for the sender to have a public IP address.
* It requires the sender and receiver to be able to open a port on their firewall.
* It requires the sender and receiver to be able to open a port on their NAT.
* It has no authentication or encryption layer, which means that you are responsible for data security.

### NFS / SMB

Native file sharing protocols are a great way to share files with a defined group of networked / trusted clients. However, they have some drawbacks:

* They require a stable p2p connection between the sender and receiver. An unstable / intermittent connection will cause the file to be corrupted or for the connection to lock up.
* They require the sender and receiver to be on the same network, or for the sender to have a public IP address.
* They require the sender and receiver to be able to open a port on their firewall.
* They require the sender and receiver to be able to open a port on their NAT.
* While they do have some authentication and encryption layers, these require additional configuration and are not enabled by default. Additionally, the RBAC model is not as flexible as other protocols.
* There is not consistent support across devices and generally requires additional software to be installed.

## Why Use `shr`

If you need to share N or more files with N or more people without relying on a third party service, cannot ensure a stable p2p connection, and cannot use torrents, then `shr` is a good protocol to consider.

## How it Works

`shr` operates over the HTTP protocol, enabling clients to access the service from any device with a web browser. `shr` can run in two modes:

* `client` mode, which is used to serve files from the local filesystem.
* `relay` mode, which acts as a gateway / NAT traversal service, proxying requests to registered `clients`.

## Usage

```bash
shr [options] <path>
  -addr string
        shr address
  -advertise string
        shr advertise address
  -id string
        shr ID
  -log-level string
        Log level (default "info")
  -port int
        shr port (default 8080)
  -relay
        shr relay mode
  -relay-addr string
        shr relay address
  -relay-key string
        shr relay key
  -relay-socket
        shr relay socket mode
  -tls-ca string
        shr TLS CA
  -tls-client-auth
        require TLS client auth (default true)
  -tls-crt string
        shr TLS certificate
  -tls-key string
        shr TLS key
  -version
        shr version
```

## Building

`shr` is written in Go, and can be built using the standard Go toolchain:

```bash
$ go build -o bin/shr cmd/shr/*.go
```

You can use the `Makefile` to build `shr` for multiple platforms:

```bash
$ make
```

## Security

### mTLS

`shr` supports mTLS for client authentication. This means that the client must present a valid certificate signed by the CA in order to access the service. The CA certificate is specified using the `-tls-ca` flag. Clients with certificates issued by this CA must present a valid certificate signed by the CA in order to access the service. By default, client auth (mTLS) is enabled. This can be disabled using the `-tls-client-auth=false` flag.

For example:

```bash
$ shr \
    -advertise 127.0.0.1 \
    -tls-ca ca.crt \
    -tls-crt server.crt \
    -tls-key server.key \
    /path/to/files
~ shr started with tls: https://127.0.0.1:8080/39cdbaf0-a04f-4e27-94d7-5236f03402a5/
```

Clients accessing this service must present a valid certificate signed by the CA in order to access the service:

```bash
$ curl \
    --cacert ca.crt \
    --cert client.crt \
    --key client.key \
    https://127.0.0.1:8080/39cdbaf0-a04f-4e27-94d7-5236f03402a5/
# with wget
$ wget \
    --recursive \
    --ca-certificate ca.crt \
    --certificate client.crt \
    --private-key client.key \
    https://127.0.0.1:8080/39cdbaf0-a04f-4e27-94d7-5236f03402a5/
```

### shr id

Each `shr` is identified by a unique ID. If the `-id` flag is not specified, a random ID will be generated. The `shr` URL will be in the format: `http(s)://<addr>:<port>/<id>/`. Any user with a netpath to the `shr` instance and knowledge of the ID can access the service.

### Relay

In `relay` mode, `shr` sits at the edge of a network and acts as a gateway / proxy for `shr` `client` instances within the network. At startup, `clients` register with the relay, and the relay will proxy requests to the `client` instance. When a `client` instance registers with the relay, it will be issued a unique key, which is used to deregister the `client` instance from the relay.

Optionally, `relays` can specify an additional `relay-key` which must be provided by client instances in order to register with the relay. This is useful for restricting access to the relay to only trusted clients. To this end, all `client-relay` communication is done on the `/_shr/*` routes, so you can also restrict these using your respective Service Mesh RBAC.

Additionally, all PKI constructs apply to the `relay` as well. `relay-client` and `client-relay` communication is done over TLS, and the `relay` can be configured to require client authentication.

### Relay Socket Mode

By default, the relay will communicate with the connected shr instances over L4 TCP connections. This requires a stable netpath from the relay to the shr instance, such as a VPN or a direct connection. In some cases, this may not be possible, and the relay may need to traverse a NAT or firewall. In this case, the relay can be configured to use "socket" mode, which will proxy requests over a websocket connection.

In relay socket mode, when the shr instance connects to the relay, it will open a long-running websocket connection to the relay over HTTP/HTTPS. When the relay receives requests for the shr instance, it will proxy the request over the websocket connection. This allows the relay to traverse NATs and firewalls, and allows the shr instance to be behind a NAT or firewall.

To enable socket mode, use the `-relay-socket` flag along with the `-relay-addr` when connecting a `shr` node. This will cause the shr node to open a websocket connection to the relay. The relay will then proxy requests over this L7 websocket connection as opposed to the default L4 TCP connection.

As socket mode requires a long-running websocket connection and is not as efficient as a direct TCP connection, it is recommended to use socket mode only when necessary.

## Examples

### Client

```bash
$ shr /path/to/files
~ shr started: http://192.168.0.9:8080/39cdbaf0-a04f-4e27-94d7-5236f03402a5/
```

```bash
$ shr \
    -id my-custom-id \
    -advertise 1.2.3.4 \
    /path/to/files
~ shr started: http://1.2.3.4:8080/my-custom-id/
```

```bash
$ shr \
    -id my-custom-id \
    -advertise 1.2.3.4 \
    -port 8081 \
    /path/to/files
~ shr started: http://1.2.3.4:8081/my-custom-id/
```

```bash
$ shr \
    -relay \
    -relay-key my-relay-key \
    -advertise 1.2.3.4 \
    -port 8081
~ shr started with relay: http://1.2.3.4:8081/
```

```bash
$ shr \
    -relay-addr https://relay.example.com \
    -id my-custom-id \
    -relay-key my-relay-key \
    /path/to/files
~ shr started with relay: http://1.2.3.4:8081/my-custom-id/
```

```bash
$ shr \
    -relay-addr https://relay.example.com \
    -id my-custom-id \
    -relay-key my-relay-key \
    -relay-socket \
    -tls-ca ca.crt \
    -tls-crt client.crt \
    -tls-key client.key \
    /path/to/files
~ shr started with relay: https://relay.example.com
```