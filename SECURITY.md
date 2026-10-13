# Security

rndis-tether runs as root, so security problems matter. Please report them privately
through GitHub: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue for them.

What is in scope: anything that lets a user or program on the Mac do more than it
could without rndis-tether (for example through the two sockets in `/var/run`), or that
lets the phone or the network make the service misbehave.
