# kcp-go
Custom folk of kcp-go(https://github.com/xtaci/kcp-go), remove 

- FEC. I think its too complicated, low efficiency because of memcopy and bytes array mangement. It's KCP/ARQ's job to deal with 
  packet loss.

- Encription. It's not the KCP's job, TLS1.3 will do the work best

make code more clean, just provide net.Conn and 
Dial function like TCP in golang.

