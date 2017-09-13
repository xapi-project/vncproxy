# vncproxy

A tool to connect securely to a remote XenServer VM's VNC console (requires
a vncviewer to be installed on your system).

## Usage

```sh
vncproxy connect <vm> --uri http://myxenserver/ --username <username> --password <password>
```

where `<vm>` is the VM's uuid or name_label.
