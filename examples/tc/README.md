# TC QoS 验证

## 环境重置

```bash
# file: ebpf/examples/tc/utils
base reset.sh
```

## Attach BPF

```bash
# file: ebpf/examples/tc
go build
ip netns exec ns2 ./tc veth1
```

## 测试

```bash
# file: ebpf/examples/tc/utils
base test.sh
```
