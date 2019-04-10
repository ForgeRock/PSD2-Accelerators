The URLs used inside this script are setup in a way that single digit hostnames point to IG, and double digit hostnames point directly to AM.

For example, login1 has an entry in /etc/hosts to point to an IG machine. Login11 has an entry in /etc/hosts to point to an AM machine.

The reason for this is to differentiate between calls sent to AM and IG; not all operations require IG. All calls using the mTLS header approach should go through IG.
