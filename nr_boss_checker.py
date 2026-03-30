import sys
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def debug(msg: str = '', end='\n') -> None:
    if DEBUG_MODE: 
        print(msg)

IV_SIZE = 0x10
PADDING_SIZE = 0xC
START_OF_CHECKSUM_DATA = 4
END_OF_CHECKSUM_DATA = PADDING_SIZE + 16

class BND4Entry:
    def __init__(self, raw_data: bytes, index: int, size: int, offset: int):
        self.index = index
        self.size = size
        self._encrypted_data = raw_data[offset:offset + size]
        self._name = f"USERDATA_{index:02d}"
        self._clean_data = b''
        
        # Extract IV from beginning of encrypted data
        self._iv = self._encrypted_data[:IV_SIZE]
        self._encrypted_payload = self._encrypted_data[IV_SIZE:]
    
    def decrypt(self) -> bytes:
        try:
            decryptor = Cipher(algorithms.AES(NR_KEY), modes.CBC(self._iv)).decryptor()
            decrypted_raw = decryptor.update(self._encrypted_payload) + decryptor.finalize()
            
            self._clean_data = decrypted_raw
            
            return self._clean_data
            
        except Exception as e:
            print(f"Error decrypting entry {self.index}: {str(e)}")
            raise

#nightreign sl2 key
NR_KEY = b'\x18\xF6\x32\x66\x05\xBD\x17\x8A\x55\x24\x52\x3A\xC0\xA0\xC6\x09'
DEBUG_MODE = False
input_file = None
input_sl2_file = "NR0000.sl2"

raw = b''
with open(input_sl2_file, 'rb') as f:
    raw = f.read()

debug("Read %u bytes from %s." % (len(raw), input_sl2_file))
if raw[0:4] != b'BND4':
    print("ERROR: 'BND4' header not found!")
    sys.exit(-1)
else:
    debug("Found BND4 header.")

num_bnd4_entries = struct.unpack("<i", raw[12:16])[0]
debug("Number of BND4 entries: %u" % num_bnd4_entries)

unicode_flag = (raw[48] == 1)
debug("Unicode flag: %r" % unicode_flag)
debug()


slot_occupancy = {}
bnd4_entries = []
BND4_HEADER_LEN = 64
BND4_ENTRY_HEADER_LEN = 32
target_entry_num = 10

pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * target_entry_num)
entry_header = raw[pos:pos + BND4_ENTRY_HEADER_LEN]

if entry_header[0:8] != b'\x40\x00\x00\x00\xff\xff\xff\xff':
    debug(f"Warning: Entry header #{target_entry_num} does not match expected magic value - skipping")

entry_size = struct.unpack("<i", entry_header[8:12])[0]
entry_data_offset = struct.unpack("<i", entry_header[16:20])[0]
entry_name_offset = struct.unpack("<i", entry_header[20:24])[0]
entry_footer_length = struct.unpack("<i", entry_header[24:28])[0]
entry_name = (raw[entry_name_offset:entry_name_offset + 24]).decode('utf-8')

debug("Entry #%u" % target_entry_num)
debug("Entry size: %u" % entry_size)
debug("Entry data offset: %u" % entry_data_offset)
debug("Entry name offset: %u" % entry_name_offset)
debug("Entry footer length: %u" % entry_footer_length)
debug("Entry name: [%s]" % entry_name)

entry = BND4Entry(
    raw_data=raw,
    index=target_entry_num,
    size=entry_size,
    offset=entry_data_offset
)

target = entry.decrypt()
debug("--------------------------")
debug()

nicknames = []
SLOT_NICKNAME_INDEX = 6498
SLOT_DATA_LEN = 656
NICKNAME_LEN = 32

for i in range(10):
    n_idx = SLOT_NICKNAME_INDEX + SLOT_DATA_LEN * i
    nickname = target[n_idx:n_idx+NICKNAME_LEN]
    if any(nickname):
        nicknames.append(nickname)

if DEBUG_MODE:
    debug("Nicknames: ", end="")
    for n in nicknames:
        debug(n.replace(b'\x00', b'').decode(), end="")
    debug()
    debug("--------------------------")
    debug()

rls_id = 0
rls_idx = None

for nickname in nicknames:
    start = SLOT_NICKNAME_INDEX + SLOT_DATA_LEN * 10
    s_idx = []
    ls_id = -1
    ls_idx = None

    while True:
        i = target.find(nickname, start)
        if i == -1:
            break

        if target[i - 20] == 0:
            s = i - 100
            sid_idx = s + 12
            sid = int.from_bytes(target[sid_idx:sid_idx+4], byteorder='little')

            if sid > ls_id:
                ls_id = sid
                ls_idx = s

        start = i + len(nickname)

    if ls_id > rls_id:
        rls_nick = nickname
        rls_id = ls_id
        rls_idx = ls_idx

print("Nickname: %s" % rls_nick.replace(b'\x00', b'').decode())
print("Last Session ID: %u" % rls_id)
debug("Last Session Index: %u" % rls_idx)

boss = target[rls_idx + 54:rls_idx + 56]
debug("Boss ID: %s" % boss.hex(' '))

NL_list = ["Gladius", "Adel", "Gnoster", "Maris", "Libra", "Fulghor", "Caligo", "Heolstor", "Harmonia", "Straghess"]

print("Boss: %s" % NL_list[boss[0]])
print("Everdark Sovereign?", end=' ')
if boss[1] == 1:
    print("YES")
else:
    print("No")
