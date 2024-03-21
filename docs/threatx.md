## About the connector
Use the ThreatX integration to enrich intel and automate enforcement actions on the ThreatX Next Gen WAF.
<p>This document provides information about the ThreatX Connector, which facilitates automated interactions, with a ThreatX server using FortiSOAR&trade; playbooks. Add the ThreatX Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with ThreatX.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet

Certified: No
## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-threatx</pre>

## Prerequisites to configuring the connector
- You must have the credentials of ThreatX server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the ThreatX server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>ThreatX</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>URL of the ThreatX server to which you will connect and perform the automated operations.
</td>
</tr><tr><td>API Key</td><td>The api key for the ThreatX server to which you will connect and perform the automated operations.
</td>
</tr><tr><td>Customer Name</td><td>The customer name for the ThreatX server to which you will connect and perform the automated operations.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Block IP Address</td><td>Add IP Address entry to blocklist in Threat X.</td><td>block_ip <br/>Investigation</td></tr>
<tr><td>Unblock IP Address</td><td>Remove IP Address entry from blocklist in Threat X.</td><td>unblock_ip <br/>Investigation</td></tr>
<tr><td>Blacklist IP Address</td><td>Add IP Address entry to blacklist in Threat X.</td><td>blacklist_ip <br/>Investigation</td></tr>
<tr><td>Unblacklist IP Address</td><td>Remove IP Address entry from blacklist in Threat X.</td><td>unblacklist_ip <br/>Investigation</td></tr>
<tr><td>Whitelist IP Address</td><td>Add IP Address entry to whitelist in Threat X.</td><td>whitelist_ip <br/>Investigation</td></tr>
<tr><td>Unwhitelist IP Address</td><td>Remove IP Address entry from whitelist in Threat X.</td><td>unwhitelist_ip <br/>Investigation</td></tr>
<tr><td>Get Entities</td><td>Returns the Entity information by Timeframe, Entity ID, Entity Name, or Entity IP from Threat X.</td><td>get_entities <br/>Investigation</td></tr>
<tr><td>Get Entity Notes</td><td>Returns the notes attached to an entity by Entity ID from Threat X.</td><td>get_entity_notes <br/>Investigation</td></tr>
<tr><td>Add Entity Notes</td><td>Adds a new note to an entity in Threat X.</td><td>add_entity_note <br/>Investigation</td></tr>
</tbody></table>

### operation: Block IP Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify IP address which you want to block in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr><tr><td>Description</td><td>(Optional) Specify the description of IP address in the block list.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Unblock IP Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify IP address which you want to block in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Blacklist IP Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify IP address which you want to blacklist in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr><tr><td>Description</td><td>(Optional) Specify the description of IP address in the blacklist.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Unblacklist IP Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify IP address which you want to unblacklist in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Whitelist IP Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify IP address which you want to whitelist in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr><tr><td>Description</td><td>(Optional) Specify the description of IP address in the whitelist.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Unwhitelist IP Address
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify IP address which you want to unwhitelist in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Get Entities
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Timeframe</td><td>Specify the timeframe for the query. Options are 1-Hour, 1-Day, 1-Week, 1-Month, or 3-Months.
</td></tr><tr><td>IP Address</td><td>(Optional) Specify IP address which you want to whitelist in Threat X. IP address or CIDR, for example: "10.1.1.1" or "10.1.1.0/24".
</td></tr><tr><td>Entity IDs</td><td>(Optional) Specify the CSV list of Entity ID hashes.
</td></tr><tr><td>Codenames</td><td>(Optional) Specify the CSV list of codenames or entity names.
</td></tr><tr><td>Actor IDs</td><td>(Optional) Specify the CSV list of actor IDs.
</td></tr><tr><td>Attack IDs</td><td>(Optional) Specify the CSV list of attack IDs.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Get Entity Notes
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Entity ID</td><td>Specify the ID of the entity which is returned from action Get Entities.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
### operation: Add Entity Notes
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Entity ID</td><td>Specify the ID of the entity which is returned from action Get Entities.
</td></tr><tr><td>Content</td><td>Specify the content which need to be added to the entity.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Ok": ""
}</pre>
## Included playbooks
The `Sample - threatx - 1.0.0` playbook collection comes bundled with the ThreatX connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the ThreatX connector.

- Add Entity Notes
- Blacklist IP Address
- Block IP Address
- Get Entities
- Get Entity Notes
- Unblacklist IP Address
- Unblock IP Address
- Unwhitelist IP Address
- Whitelist IP Address

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
