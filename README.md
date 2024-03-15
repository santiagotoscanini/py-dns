## py-dns


#### Running the server
Run the DNS server with:

```bash
./server.sh
```

It only has a few hardcoded DNS entries for A records, as it's a simple example of a DNS server to learn how to parse DNS requests and respond to them.

If instead we want to run it in a forwarding mode, we can use the following command:

```bash
./server.sh --resolver <ip>:<port>
```

#### Testing

Test with:

```shell
dig @127.0.0.1 -p 2053 example.com
```
