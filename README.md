### NOTES: Sophos (MDR)

- NDR Data Engine IDS Engine using machine learning algo to sieve packets for malicious behavious

- NDR on switches SPAN (Switched Port Analyzer) port <VLAN ID (4095)>
	+ NDR investigation console saves data (metadata) for 30days, while
	+ While NO data is stored until network session ends, NDR Sensor (and console) sends metadata to Sophos DataLake for 90 days (default, but plan for annual can be extended)

- NDR Deployment on virtual/cloud/hardware

-----------------------------------------------------------
= Endpoint
= Detection
= Email
= FW
= CLOUD Optix
= Mobile
= M365
= ZTNA*
= NDR
= APT (Threat) Detection

-----------------------------------------------------------
Resource Thresholds
+ IF `SophosOSQuery.exe` >= 250mb RAM || CPU > 60%
+ IF `SophosOSQueryExtension.exe` > 250mb
+ IF query.response > 10mb (from a single device)
+ IF query.request > 50kb || < 15 char

-----------------------------------------------------------
XDR Data Lake

Live Discover
+ Max of 6 variables in new/edited queries

-----------------------------------------------------------
SQL
+ `<> 'case_sensitive'`
+ `NOT LIKE` '%case_insensitive%'
+ `LIKE %string%` // '$strict$'  // '%ends_with'
+ `DISTINCT` 	// for uniq value
+ `JOIN` 	// two, or more TABLES
+ `LEFT || JOIN`
+ `GROUP BY` ``// group data with same VALUES into summary rows
+ `WHERE time > strftime ('%s', 'now', '-30 minutes')`
+ `WHERE time > datetime (TIME, UNIX_EPOCH, LOCALTIME)` e.g (, , )

-----------------------------------------------------------
Threat Graphs
+ Detections held in Lakes, active in <= 90days

Live Response
+ START/STOP services remotely
+ Admin-level Remote Access to managed endpoints & servers

-----------------------------------------------------------
Live Discover
+ Check what services are running
+ FOR:: SOC IT Operations
+ bin `PDQDeploy`

-----------------------------------------------------------
Inbound rule to allow comms
+ (Sophos) Message Relay uses TCP::8190 to communicate policy & reporting data to devices, and
+ port 8191 is available and accessible to computers that will update from the cache

-----------------------------------------------------------
+ When a device health turns red, the Sophos Firewall shares the IP address, user identity, and health status (red) of that device with networked devices via Security Heartbeat.
+ The `Role-based email alerts` allows specific email alert notifications to be sent to users who do not have Sophos Central access
+ Sophos recommends scheduling the Windows Active Directory Synchronization Utility to run once every hour.
+ The installation directory of Sophos Server Protection for Linux is `/opt/sophos-spl`
+ Sophos Anti-Tamper Service cannot be running when attempting to remove the Sophos Endpoint Agent from a Windows device.
+ The report that displays a list of all detected controlled applications is the Application Control Report.
+ New security features are enabled in the threat protection policy by default - I said TRUE, but marked wrong
+ Marking an alert as resolved in Sophos Central does not verify that the threat has been removed; it only clears the alert from the console
+ The Events Report allows you to filter the event type returned.
+ Live Response is enabled in Global Settings within Sophos Central.
+ The available pivoting options of a Live Discover query are based on the query results (returned data fields).
+ 2GB daily data allowance in gigabytes per device to the Data Lake
+ "API" integration requires authentication information from the product for configuration
+ 4095 configuring the SPAN ports on a virtual machine
+ scheduled reports expire in 6 months
+ A user or user group is identified as synchronized or centrally-managed by the directory sync icon shown next to it in Sophos Central. (icon next to the user/user group name)
+ 10 maximum number of API credentials you can add to Sophos Central
