import sys
import struct
# import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def debug(msg: str = '') -> None:
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

# parser = argparse.ArgumentParser(description='Nightlord checker in ER-NR SL2 save files.')
# parser.add_argument('input_sl2', metavar='input.sl2', help='the SL2 save file to use as input (this will not be modified).')
# args = parser.parse_args()

# input_sl2_file = args.input_sl2
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

nickname = target[6498:6530]
print("Nickname: %s" % nickname.replace(b'\x00', b'').decode())

s_idx = []
start = 6600

while True:
    i = target.find(nickname, start)
    if i == -1:
        break

    if target[i - 20] == 0:
        s_idx.append(i - 100)

    start = i + len(nickname)

ls_id = -1
ls_idx = None

for s in s_idx:
    sid_idx = s + 12
    sid = int.from_bytes(target[sid_idx:sid_idx+4], byteorder='little')

    if sid > ls_id:
        ls_id = sid
        ls_idx = s
        
print("Last Session ID: %u" % ls_id)
debug("Last Session Index: %u" % ls_idx)

boss = target[ls_idx + 54:ls_idx + 56]
debug("Boss ID: %s" % boss.hex(' '))

NL_list = ["Gladius", "Adel", "Gnoster", "Maris", "Libra", "Fulghor", "Caligo", "Heolstor", "Harmonia", "Straghess"]

print("Boss: %s" % NL_list[boss[0]])
print("Everdark Sovereign?", end=' ')
if boss[1] == 1:
    print("YES")
else:
    print("No")

# print()
# print()
# input("Press Enter to Exit...")
