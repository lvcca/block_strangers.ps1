# block_strangers.ps1
Dynamic firewall to block strange IPs

Creates SUS_HOSTS.txt file to desktop.
Creates two firewall rules in both INCOMING and OUTGOING traffic.

Block IPs based on FQDN recognized by trusted DNS server
If IP not recognized it will be added to SUS_HOSTS.txt

Requires Admin Credentials

![image](https://user-images.githubusercontent.com/49540886/172257633-f959e49f-baa1-45d2-84d0-8079a326bd21.png)

![image](https://user-images.githubusercontent.com/49540886/172030233-5dcbc4d5-6ea0-4928-9040-c2b7ac34997d.png)
![image](https://user-images.githubusercontent.com/49540886/172030231-fb144cf3-e462-4df1-be95-c8a31ff0c8b9.png)
