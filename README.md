# netmon

A simple client/server pair for enumerating all active devices on ones home 
network. The client code, written in Go, queries the ARP table of one's 
router/switch, and iterates through each client attempting to ping the host, 
and checks common ports failing that. The host list is then uploaded to a 
DynamoDB.

The server is a very simple flask app that leverages Google OAuth to 
authenticate clients, and then displays the content living in the Dynamo DB.

## TODO

    - Build out installation scripts for the client
    - Better host "online" checks
    - More server support, differentials of new hosts, color coding of uptime
