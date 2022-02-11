package main

// A simple client-side utility to scan a network for active devices. This
// client makes use of SNMP to query the Router/Switch ARP tables to enumerate
// all hosts which have been seen on the network. It then attempts to determine
// whether or not each host is online, and stashes all the relevant info to
// an AWS Dynamo table.
//
// TODOs:
// 1.) Filesystem logging as opposed to stdout
// 2.) Better connectivity checks, port scanning
// 3.) Parallelization
// 4.) Installation scripts in bash, systemd init files.

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"

	g "github.com/gosnmp/gosnmp"
	fp "github.com/tatsushid/go-fastping"
)

var dynamoTable string = strings.TrimSpace(os.Getenv("NETMON_DYNAMO_TABLE"))

type NetworkHost struct {
	ipAddress  string
	macAddress string
	isActive   bool
	lastActive int
}

func Ping(target string) bool {
	pinger := fp.NewPinger()
	pinger.AddIPAddr(&net.IPAddr{IP: net.ParseIP(target)})
	pinger.MaxRTT = time.Second

	var res time.Duration = -1

	pinger.OnRecv = func(addr *net.IPAddr, t time.Duration) {
		res = t
	}
	pinger.OnIdle = func() {}

	perr := pinger.Run()
	if perr != nil || res == -1 {
		return false
	}
	return true
}

func CheckPort(target string, port int) bool {
	to := time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), to)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

func GetHostDynamo(mac string, client dynamodb.DynamoDB) NetworkHost {

	res, err := client.GetItem(
		&dynamodb.GetItemInput{
			TableName: aws.String(dynamoTable),
			Key: map[string]*dynamodb.AttributeValue{
				"mac_address": {
					S: aws.String(mac),
				},
			},
		},
	)

	if err != nil {
		fmt.Printf("[-] Query to DynamoDB failed with %s\n", err.Error())
		return NetworkHost{}
	}
	if res.Item == nil {
		fmt.Print("[-] DynamoDB returned an emtpy item\n.")
		return NetworkHost{}
	}

	// This isn't working so for now we do it the shitty way
	//err = dynamodbattribute.UnmarshalMap(res.Item, &host)
	//if err != nil {
	//	fmt.Printf("Failed to deserialize Dynamo response for %s.\n", mac)
	//}
	lastAct, err := strconv.Atoi(*res.Item["last_active"].N)
	host := NetworkHost{*res.Item["ip_address"].S, *res.Item["mac_address"].S, *res.Item["is_active"].BOOL, lastAct}

	return host
}

func UpsertHost(host NetworkHost, client dynamodb.DynamoDB) bool {

	fetchedHost := GetHostDynamo(host.macAddress, client)
	if fetchedHost.macAddress != "" {
		input := &dynamodb.UpdateItemInput{
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":ipaddr": {
					S: aws.String(host.ipAddress),
				},
				":active": {
					BOOL: aws.Bool(host.isActive),
				},
				":lastActive": {
					N: aws.String(strconv.FormatInt(int64(host.lastActive), 10)),
				},
			},
			TableName: aws.String(dynamoTable),
			Key: map[string]*dynamodb.AttributeValue{
				"mac_address": {
					S: aws.String(host.macAddress),
				},
			},
			ReturnValues:     aws.String("UPDATED_NEW"),
			UpdateExpression: aws.String("set ip_address = :ipaddr, is_active = :active, last_active = :lastActive"),
		}
		_, err := client.UpdateItem(input)
		if err != nil {
			log.Fatalf("Got error calling UpdateItem: %s", err)
		}
		return true
	} else {
		_, err := client.PutItem(
			&dynamodb.PutItemInput{
				TableName: aws.String(dynamoTable),
				Item: map[string]*dynamodb.AttributeValue{
					"ip_address": {
						S: aws.String(host.ipAddress),
					},
					"mac_address": {
						S: aws.String(host.macAddress),
					},
					"is_active": {
						BOOL: aws.Bool(host.isActive),
					},
					"last_active": {
						N: aws.String(strconv.FormatInt(int64(host.lastActive), 10)),
					},
				},
			},
		)
		if err != nil {
			fmt.Printf("[-] Failed to insert host %s.\n", host.macAddress)
			return false
		}
		return true
	}
}

func EnumNetHosts() map[string]NetworkHost {
	// OID for IP to Phys ARP Table
	arpOid := []string{"1.3.6.1.2.1.4.35"}
	g.Default.Target = strings.TrimSpace(os.Getenv("NETMON_SNMP_TARGET"))
	g.Default.Community = strings.TrimSpace(os.Getenv("NETMON_SNMP_COMMUNITY"))
	g.Default.Timeout = time.Second

	err := g.Default.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to %s with %v", g.Default.Target, err)
	}
	defer g.Default.Conn.Close()

	result, err2 := g.Default.GetBulk(arpOid, 0, 100)
	if err2 != nil {
		log.Fatalf("Failed to get OIDS from target with %v", err2)
		os.Exit(1)
	}

	hosts := make(map[string]NetworkHost)
	connPorts := []int{21, 22, 23, 25, 80, 443, 3389, 8000, 8080, 8081, 8088, 8443}
	for _, res := range result.Variables {

		// Parse out the IP, which is stored in the Name of our response
		oid := strings.Split(res.Name, ".")
		hostIp := strings.Join(oid[len(oid)-4:], ".")
		if !strings.HasPrefix(hostIp, "172") {
			continue
		}

		bytes := res.Value.([]byte)
		if len(bytes) != 6 {
			fmt.Printf("[-] Found invalid host: %s", hostIp)
			fmt.Println(bytes)
			continue
		}
		mac := fmt.Sprintf(
			"%02x:%02x:%02x:%02x:%02x:%02x",
			bytes[0],
			bytes[1],
			bytes[2],
			bytes[3],
			bytes[4],
			bytes[5],
		)
		isActive := Ping(hostIp)

		// If the host is already active, we're done
		lastActive := 0
		if !isActive {
			// If Ping doesn't work check to see if there's open ports
			for _, port := range connPorts {
				isActive = CheckPort(hostIp, port)
				if isActive {
					break
				}
			}
		} else {
			lastActive = int(time.Now().Unix())
		}

		hosts[mac] = NetworkHost{hostIp, mac, isActive, lastActive}
	}
	return hosts
}

func main() {
	hosts := EnumNetHosts()
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	client := dynamodb.New(sess)
	for _, host := range hosts {
		UpsertHost(host, *client)
	}
}
