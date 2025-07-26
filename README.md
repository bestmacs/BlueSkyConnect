# BlueSky

BlueSky establishes and maintains an SSH tunnel initiated by your client’s computer to a BlueSky server. The tunnel allows two connections to come back to the computer from the server: SSH and VNC. The SSH and VNC services on the computer are the ones provided by the Sharing.prefpane.

You use an Admin app to connect via SSH to the BlueSky server and then follow the tunnel back to your client computer. You select which computer by referencing its BlueSky ID as shown in the web admin.

Apps are provided to connect you to remote Terminal (SSH), Screen Sharing (VNC), and File/Folder copying (SCP). You still need to be able to authenticate as a user on the target computer.

Since BlueSky from your client computers is an outgoing connection most SMB networks won’t block it. In enterprise environments, BlueSky can read the proxy configuration in system preferences and send the tunnel through a proxy server.

Read more in the [Wiki](https://github.com/BlueSkyTools/BlueSkyConnect/wiki)

Visit the #bluesky channel of MacAdmins Slack for help.

Want to contribute?  Here's our [Trello board](https://trello.com/invite/b/aM8Y7XzR/4e6acab01031bd5aac72a91347d5e875/bluesky-kanban)

## Docker Information

Information regarding running BlueSky with docker can be found [in this README](https://github.com/BlueSkyTools/BlueSkyConnect/blob/master/docker/README.md)
