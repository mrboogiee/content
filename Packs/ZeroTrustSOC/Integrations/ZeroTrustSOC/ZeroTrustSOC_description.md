## ZeroTrustSOC

This integration connects Cortex XSIAM (or XSOAR) to the ZeroTrustSOC public API
(`https://api.on2it.net/v3/`). It lets analysts look up Protect Surfaces by their content
type (IP, hostname, identity, container, cloud resource), manage ON2IT cases end-to-end,
and mirror case state between XSIAM and the ON2IT SOC.

### How to get an API token

Tokens are issued by ON2IT Service Desk. Send a request from your corporate email to
**servicedesk@on2it.net** asking for a Zero Trust SOC API token, mention the Cortex
XSIAM/XSOAR integration, and the team will reply with a bearer token. Paste the token
into the **API Token** credentials field below; no username is required.
