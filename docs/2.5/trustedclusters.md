# Trusted Clusters

If you haven't already looked at the introduction to [Trusted Clusters](admin-guide.md#trusted-clusters) 
in the Admin Guide we recommend you review that for an overview before continuing with this guide.

The Trusted Clusters chapter in the Admin Guide
offers an example of a simple configuration which:

* Uses a static cluster join token defined in a configuration file.
* Does not cover inter-cluster role based access control (RBAC).

This guide's focus is on more in-depth coverage of trusted clusters features and will cover the following topics:

* How to add and remove trusted clusters using CLI commands.
* Enable/disable trust between clusters.
* Establish permissions mapping between clusters using Teleport roles.

## Introduction 

As explained in the [architecture document](architecture/#core-concepts),
Teleport can partition compute infrastructure into multiple clusters.
A cluster is a group of SSH nodes connected to the cluster's _auth server_
acting as a certificate authority (CA) for all users and nodes.

To retrieve an SSH certificate, users must authenticate with a cluster through a
_proxy server_. So, if users want to connect to nodes belonging to different
clusters, they would normally have to use different `--proxy` flags for each
cluster. This is not always convenient.

The concept of _trusted clusters_ allows Teleport administrators to connect
multiple clusters together and establish trust between them. Trusted clusters
allow users of one cluster to seamlessly SSH into the nodes of another cluster
without having to "hop" between proxy servers. Moreover, users don't even need
to have a direct connection to other clusters' proxy servers. The user
experience looks like this:

```bash
# login using the "main" cluster credentials:
$ tsh login --proxy=main.example.com

# SSH into some host inside the "main" cluster:
$ tsh ssh host

# SSH into the host located in another cluster called "east"
# The connection is established through main.example.com:
$ tsh --cluster=east ssh host

# See what other clusters are available
$ tsh clusters
```

Trusted clusters also have their own restrictions on user access, i.e. 
_permissions mapping_ takes place. 

## Join Tokens

Lets start with the diagram of how connection between two clusters is established:

![Tunnels](img/tunnel.svg)

The first step in establishing a secure tunnel between two clusters is for the
_trusting_ cluster "east" to connect to the _trusted_ cluster "main". When this
happens for _the first time_, clusters know nothing about each other, thus a
shared secret needs to exist in order for "main" to accept the connection from
"east". 

This shared secret is called a "join token". There are two ways to create join
tokens: to statically define them in a configuration file, or to create them on
the fly using `tctl` tool.

!!! tip "Important":
    It is important to realize that join tokens are only used to establish the
    connection for the first time. The clusters will exchange certificates and
    won't be using the token to re-establish the connection in the future.

### Static Tokens

To create a static join token, update the configuration file on "main" cluster 
to look like this:

```bash
# fragment of /etc/teleport.yaml:
auth_service:
  enabled: true
  tokens:
  - trusted_cluster:join-token
```

This token can be used unlimited number of times. 

### Dynamic Tokens

Creating a token dynamically with a CLI tool offers the advantage of applying a
time to live (TTL) interval on it, i.e. it will be impossible to re-use such
token after a specified period of time.

To create a token using the CLI tool, execute this command on the _auth server_
of cluster "main":

```bash
$ tctl nodes add --ttl=5m --roles=trustedcluster --token=join-token
``` 

Users of Teleport will recognize that this is the same way you would add any node to a cluster.

* The token created above can be used multiple times and has an expiration time of 5 minutes.
* If you omit the `--token` flag `tctl` will generate one for you.

### Security Implications

Consider the security implications when deciding which token method to use.
Short lived tokens decrease the window for attack but make automation a bit
more complicated. 

## RBAC

!!! warning "Version Warning":
    The RBAC section is applicable only to Teleport Enterprise. The open source
    version does not suppport SSH roles.

When a _trusting_ cluster "east" from the diagram above establishes trust with
the _trusted_ cluster "main", it needs a way to configure which users from
"main" should be allowed in and what permissions should they have. Teleport
Enterprise uses _role mapping_ to achieve this.

Consider the following:

* Both clusters "main" and "east" have their own locally defined roles.
* Every user in Teleport Enterprise is assigned a role. 
* When creating a _trusted cluster_ resource, the administrator of "east" must
  define how roles from "main" map to roles on "east".

### Example 

Lets make a few assumptions for this example:

* The cluster "main" has two roles: _user_ for regular users and _admin_ for
  local administrators.

* We want administrators from "main" (but not regular users!) to have
  restricted access to "east". We want to deny them access to machines
  with "environment=production" label.

First, we need to create a special role for main users on "east":

```bash
# save this into main-user-role.yaml on the east cluster and execute:
# tctl create main-user-role.yaml
- kind: role
  version: v3
  metadata:
    name: mainuser
  spec:
    allow:
      node_labels:
        '*': '*'
    deny:
      node_labels:
        "environment": "production"
```

Now, we need to establish trust between roles "main:admin" and "east:mainuser". This is 
done by creating a trusted cluster [resource](admin-guide/#resources) on "east"
which looks like this:

```bash
# save this as main-cluster.yaml on the auth server of "east" and then execute:
# tctl create main-cluster.yaml
kind: trusted_cluster
version: v1
metadata:
  name: "main"
spec:
  enabled: true
  role_map:
    - remote: "admin"
      local: [mainuser]
  token: "join-token"
  tunnel_addr: main.example.com:3024
  web_proxy_addr: main.example.com:3080
```

What if we wanted to let _any_ user from "main" to be allowed to connect to
nodes on "east"? In this case we can use a wildcard `*` in the `role_map` like this:

```bash
role_map:
  - remote: "*"
    local: [mainuser]
```

## Using Trusted Clusters

Now an admin from the main cluster can now see and access the "east" cluster:

```bash
# login into the main cluster:
$ tsh --proxy=proxy.main login admin
```

```bash
# see the list of available clusters
$ tsh clusters

Cluster Name   Status
------------   ------
main           online
east           online
```

```bash
# see the list of machines (nodes) behind the eastern cluster:
$ tsh --cluster=east ls

Node Name Node ID            Address        Labels
--------- ------------------ -------------- -----------
db1.east  cf7cc5cd-935e-46f1 10.0.5.2:3022  role=db-master
db2.east  3879d133-fe81-3212 10.0.5.3:3022  role=db-slave
```

```bash
# SSH into any node in "east":
$ tsh --cluster=east ssh root@db1.east
```


!!! tip "Note":
    Trusted clusters work only one way. So, in the example above users from "east" 
	cannot see or connect to the nodes in "main".

### Disabling Trust

To temporarily disable trust between clusters, i.e. to disconnect the "east"
cluster from "main", edit the YAML definition of the trusted cluster resource
and set `enabled` to "false", then update it:

```bash
$ tctl create --force cluster.yaml
```


## How does it work?

At a first glance, Trusted Clusters in combination with RBAC may seem
complicated. However, it is based on SSH
certificate-based authentication which is fairly easy to reason about:

One can think of an SSH certificate as a "permit" issued and time-stamped by a
certificate authority. A certificate contains three important pieces of data:

* List of identities you can assume (usually called "principals")
* Expiration date
* Signature of the certificate authority who issued it (the _auth_ server)

Every role is encoded in a certifiate as yet another principal. When a user
from "main" connects to "east", the auth server of "east" does three checks:

* Checks that the certificate signature matches one of the trusted clusters
* Checks that the certificate is not expired
* Tries to find a local role which maps to the list of principals found in the certificate

## Troubleshooting

There are three common types of problems Teleport administrators can run into when configuring 
trust between two clusters:

* **HTTPS configuration**: when the main cluster uses a self-sgined or invalid HTTPS certificate.

* **Connectivity problems**: when a trusting cluster "east" does not show up in
  `tsh clusters` output on "main".

* **Access problems**: when users from "main" get "access denied" error messages
  trying to connect to nodes on "east".

### HTTPS configuration

If the web_proxy_addr endpoint of the main cluster uses a self-signed or invalid HTTPS certificate, 
you will get an error: "the trusted cluster uses misconfigured HTTP/TLS certificate". For ease of 
testing the teleport daemon of "east" can be started with  `--insecure` CLI flag to accept 
self-signed certificates. Make sure to configure HTTPS properly and remove the insecure flag for production use.

### Connectivity Problems

To troubleshoot connectivity problems, enable verbose output for the auth
servers on both clusters. Usually this can be done by adding `--debug` flag to
`teleport start --debug`. You can also do this by updating the configuration
file for both auth servers:

```bash
# snippet from /etc/teleport.yaml
teleport:
  log:
    output: stderr
    severity: DEBUG
```

On systemd-based distributions you can watch the log output via:

```bash
$ sudo journalctl -fu teleport
```

Most of the time you will find out that either a join token is
mismatched/expired, or the network addresses for `tunnel_addr` or
`web_proxy_addr` cannot be reached due to pre-existing firewall rules or
how your network security groups are configured on AWS.

### Access Problems

Troubleshooting access denied messages can be challenging. A Teleport administrator
should check to see the following:

* Which groups a user is assigned on "main" when they retreive their SSH
  certificate via `tsh login`.
* How "east" performs group mappping when a user from "main" tries to connect.

Both of these facts are reflected in the Teleport audit log. By default, it is
stored in `/var/lib/teleport/log` on a _auth_ server of a cluster. Check the
audit log messages on both clusters to get answers for the questions above.
