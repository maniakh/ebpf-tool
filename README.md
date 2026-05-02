# findo

`findo`, eBPF + Go ile yazilmis minimal runtime anomaly detector'dur.
Linux'ta `execve`, `openat`, `setuid` olaylarini izler ve supheli davranislari anlik alert olarak verir.

## Ne tespit eder?
- `tmp_exec`: `/tmp`, `/dev/shm`, `/var/tmp` altindan calistirma
- `web_shell`: web surecinden shell spawn
- `downloader`: shell altinda `curl`/`wget`
- `credential`: `/etc/shadow` veya `~/.ssh/id_*` erisimi
- `kernel_tamper`: `/proc/kcore`, `/dev/mem`, `/dev/kmem`
- `priv_esc`: supheli setuid / root shell paterni

## Gereksinimler
- Linux kernel 5.8+
- Go 1.22+
- `clang`, `llvm`, `libbpf-dev`, `bpftool`, `git`

## Hizli calistirma
```bash
git clone https://github.com/maniakh/ebpf-tool.git
cd ebpf-tool
bash ./run findo
```

## Calisirken komutlar
- `-h` : yardim
- `-v` : surum
- `stats` : event/alert sayaclarini goster
- `open whitelist` : whitelist dosyasini goster
- `open log` : log dosyasinin son satirlarini goster
- `exit` : cikis

## Log ve ayarlar
- varsayilan log: `findo.log`
- log yolu: `EBPF_TOOL_LOG=/var/log/findo.log bash run findo`
- dedup saniyesi: `FINDO_DEDUP_SEC=10`
- whitelist dosyasi: `FINDO_WHITELIST=whitelist.txt`

## Not
- Alertler terminalde tablo formatinda gosterilir.
- Ayrintili alert satirlari `findo.log` dosyasina yazilir.

