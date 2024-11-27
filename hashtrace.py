import re
from sys import argv
import zlib
from hashlib import md5
from Crypto.Hash import MD4 
import base64

# Sample logo
version = 1.2
logo = f"""
#      ___          ___          ___          ___                 ___         ___          ___          ___       #
#     /__/\        /  /\        /  /\        /__/\        ___    /  /\       /  /\        /  /\        /  /\      #
#     \  \:\      /  /::\      /  /:/_       \  \:\      /  /\  /  /::\     /  /::\      /  /:/       /  /:/_     #
#      \__\:\    /  /:/\:\    /  /:/ /\       \__\:\    /  /:/ /  /:/\:\   /  /:/\:\    /  /:/       /  /:/ /\    #
#  ___ /  /::\  /  /:/~/::\  /  /:/ /::\  ___ /  /::\  /  /:/ /  /:/~/:/  /  /:/~/::\  /  /:/  ___  /  /:/ /:/_   #
# /__/\  /:/\:\/__/:/ /:/\:\/__/:/ /:/\:\/__/\  /:/\:\/  /::\/__/:/ /:/__/__/:/ /:/\:\/__/:/  /  /\/__/:/ /:/ /   #
# \  \:\/:/__\/\  \:\/:/__\/\  \:\/:/~/:/\  \:\/:/__\/__/:/\:\  \:\/:::::|  \:\/:/__\/\  \:\ /  /:/\  \:\/:/ /:/  # 
#  \  \::/      \  \::/      \  \::/ /:/  \  \::/    \__\/  \:\  \::/~~~~ \  \::/      \  \:\  /:/  \  \::/ /:/   #
#   \  \:\       \  \:\       \__\/ /:/    \  \:\         \  \:\  \:\      \  \:\       \  \:\/:/    \  \:\/:/    #
#    \  \:\       \  \:\        /__/:/      \  \:\         \__\/\  \:\      \  \:\       \  \::/      \  \::/     #
#     \__\/        \__\/        \__\/        \__\/               \__\/       \__\/        \__\/        \__\/      #
#                                                                                                                 #
#            .-""-.                                                                                               #
#           / .--. \\                                                                                              #
#          / /    \ \                                                                                             #
#          | |    | |                                                                                             #
#          | |.-""-.|                                                                                             #
#         ///`.::::.`\\                                                                       [+] version ==> v{version} #
#        ||| ::/  \:: ;                                                                                           #
#        ||; ::\__/:: ;                                                                                           #
#         \\\ '::::'  /                                                                                            #
#          `=':-..-'`                                                                                             # 
###################################################################################################################
-------------------------------------------------------------------------------------------------------------------------------------------------------
                                                     _            _      _ _    _   
                                                    | |_  __ _ __| |_   | (_)__| |_ 
                                                    | ' \/ _` (_-< ' \  | | (_-<  _|
                                                    |_||_\__,_/__/_||_| |_|_/__/\__|
                                 
-------------------------------------------------------------------------------------------------------------------------------------------------------

[Supported hashes => {{ MD5, MD4, SHA-1, SHA-256, SHA-512, CRC32, CRC32b, CRC32b-PHP, NTLM, CRC32_padded, SHA-224, SHA-384, SHA3-256, SHA3-512, Blake2b, RIPEMD-160, Whirlpool, Adler-32, FCS-32, GHash-32-3, GHash-32-5, FNV-132, Fletcher-32, Joaat, ELF-32, XOR-32, Microsoft Outlook PST, Dahua, bcrypt, PBKDF2, Argon2i, Argon2d, Argon2id, pbkdf2-sha256_django, pbkdf2-sha1_django, pbkdf2-sha512_django, pbkdf2-sha256(salted, hex_format), pbkdf2-sha512(salted, hex_format), pbkdf2-sha1(salted, hex_format) }}]

--------------------------------------------------------------------------------------------------------------------------------------------------------
"""


# Dictionary to map hash identifiers to algorithm names
algorithms = {
    "106020": "MD5",
    "106030": "MD4",
    "106040": "SHA-1",
    "106060": "SHA-256",
    "106080": "SHA-512",
    "106100": "CRC32",
    "106102": "CRC32b",
    "106103": "CRC32b-PHP",
    "106120": "NTLM",
    "106101": "CRC32_padded",
    "106140": "SHA-224",
    "106160": "SHA-384",
    "106180": "SHA3-256",
    "106200": "SHA3-512",
    "106220": "Blake2b",
    "106240": "RIPEMD-160",
    "106260": "Whirlpool",
    "106104": "Adler-32",
    "106105": "FCS-32",
    "106106": "GHash-32-3",
    "106107": "GHash-32-5",
    "106108": "FNV-132",
    "106109": "Fletcher-32",
    "106110": "Joaat",
    "106111": "ELF-32",
    "106112": "XOR-32",
    "106113": "Microsoft Outlook PST",
    "106114": "Dahua",
    "bcrypt (salted)": "bcrypt",  # Add bcrypt salted hash type
    "PBKDF2 (salted)": "PBKDF2",  # Add PBKDF2 salted hash type
    "Argon2i(salted)": "Argon2i",
    "Argon2d(salted)": "Argon2d",
    "Argon2id(salted)": "Argon2id",
    "pbkdf2-sha256 (salted)" : "pbkdf2-sha256_django",
    "pbkdf2-sha1 (salted)" : "pbkdf2-sha1_django",
    "pbkdf2-sha512 (salted)" : "pbkdf2-sha512_django",
    "pbkdf2-sha256 (salted, hex format)" : "pbkdf2-sha256(salted ,hex_format)",
    "pbkdf2-sha512 (salted, hex format)" : "pbkdf2-sha512 (salted, hex format)",
    "pbkdf2-sha1 (salted, hex format)" : "pbkdf2-sha1 (salted, hex format)"
}

# Define hash-check functions
def MD5(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106020")

def MD4_T(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106030")

def SHA1(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{40}$', hash):
        jerar.append("106040")

def SHA256(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{64}$', hash):
        jerar.append("106060")

# def SHA512(hash, jerar):
#     if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
#         jerar.append("106080")
def SHA512(hash, jerar):
    # Accept both 96 and 128 hexadecimal character lengths for SHA-512
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106080")

def CRC32(hash, jerar):
    # Check for 8-character CRC32 in hex or 0x-prefixed format
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash) or re.fullmatch(r'^0x[A-Fa-f0-9]{8}$', hash):
        jerar.append("106100")

def CRC32b(hash, jerar):
    # CRC32b typically uses the same 8-hex character format, so add a separate identifier for CRC32b
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash) or re.fullmatch(r'^0x[A-Fa-f0-9]{8}$', hash):
        jerar.append("106102")

def CRC32b_PHP(hash, jerar):
    # CRC32b-PHP also uses 8-character hexadecimal format, so add a unique identifier for CRC32b-PHP
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash) or re.fullmatch(r'^0x[A-Fa-f0-9]{8}$', hash):
        jerar.append("106103")

def CRC32_padded(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106101")  # A unique code to differentiate it

def Adler32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106104")

# Function to identify FCS-32 hash
def FCS32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106105")

# Function to identify GHash-32-3 hash
def GHash32_3(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106106")

# Function to identify GHash-32-5 hash
def GHash32_5(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106107")

# Function to identify FNV-132 hash
def FNV132(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106108")

# Function to identify Fletcher-32 hash
def Fletcher32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106109")

# Function to identify Joaat hash
def Joaat(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106110")

# Function to identify ELF-32 hash
def ELF32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106111")

# Function to identify XOR-32 hash
def XOR32(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106112")

# Function to identify Microsoft Outlook PST hash
def Microsoft_Outlook_PST(hash, jerar):
    if re.fullmatch(r'^\$PST\$.{64}$', hash) or re.fullmatch(r'^[a-fA-F0-9]{32}$', hash) :
        jerar.append("106113")

# Function to identify Dahua hash
def Dahua(hash, jerar):
    if re.fullmatch(r'^[A-Fa-f0-9]{8}$', hash):
        jerar.append("106114")

def NTLM(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{32}$', hash):
        jerar.append("106120")

def SHA224(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{56}$', hash):
        jerar.append("106140")

def SHA384(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{96}$', hash):
        jerar.append("106160")

def SHA3_256(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{64}$', hash):
        jerar.append("106180")

def SHA3_512(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106200")

def Blake2b(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106220")

def RIPEMD160(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{40}$', hash):
        jerar.append("106240")

def Whirlpool(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{128}$', hash):
        jerar.append("106260")

def argon2i(hash , jerar):
    """Check if the hash is an Argon2i hash."""
    pattern = r'^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'
    x = bool(re.match(pattern, hash))
    if x == True:
        jerar.append("Argon2i(salted)")

def argon2d(hash , jerar):
    """Check if the hash is an Argon2d hash."""
    pattern = r'^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'
    check = bool(re.match(pattern, hash))
    if check == True:
        jerar.append("Argon2d(salted)")

def argon2id(hash , jerar):
    """Check if the hash is an Argon2id hash."""
    pattern = r'^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'
    check = bool(re.match(pattern, hash))
    if check == True:
        jerar.append("Argon2id(salted)")

def bcrypt(hash, jerar):
    if re.fullmatch(r'^\$2[ayb]\$[0-9]{2}\$[./a-zA-Z0-9]{53}$', hash):
        jerar.append("bcrypt (salted)")

# Function to identify PBKDF2 (salted)
def PBKDF2(hash, jerar):
    if re.fullmatch(r'^[a-fA-F0-9]{64}[:][a-fA-F0-9]{32}$', hash) or re.fullmatch(r'^\$pbkdf2-[a-zA-Z0-9]+(\$[0-9]+){1}(\$[a-fA-F0-9]+){2}$', hash):
        jerar.append("PBKDF2 (salted)")

def pbkdf2_sha256(hash, jerar):
    """Check if the hash is a PBKDF2-SHA256 hash."""
    
    # Regular expressions to check for PBKDF2-SHA256 formats
    # pattern1 = r'^\$pbkdf2-sha256\$(iterations=)?\d+\$(?:[a-zA-Z0-9+/=]{22,})\$(?:[a-f0-9]{64})$'  # Base64 format
    pattern1 = r'^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/]+(?:={0,2})?\$[a-zA-Z0-9+/]+(?:={0,2})?$'
    pattern2 = r'^[a-fA-F0-9]{64}$'  # Hexadecimal format, both salt and hash

    # Check if the hash matches either pattern
    if re.fullmatch(pattern1, hash):
        jerar.append("pbkdf2-sha256 (salted)")   
    elif re.fullmatch(pattern2, hash):
        jerar.append("pbkdf2-sha256 (salted, hex format)")

def pbkdf2_sha1(hash, jerar):
    """Check if the hash is a PBKDF2-SHA1 hash."""
    
    # Regular expressions to check for PBKDF2-SHA1 formats
    # pattern1 = r'^\$pbkdf2-sha1\$(iterations=)?\d+\$(?:[a-zA-Z0-9+/=]{22,})\$(?:[a-f0-9]{40})$'  # Base64 format
    pattern1 = r'^pbkdf2_sha1\$\d+\$[a-zA-Z0-9+/]+(?:={0,2})?\$[a-zA-Z0-9+/]+(?:={0,2})?$'
    pattern2 = r'^[a-fA-F0-9]{40}$'  # Hexadecimal format, both salt and hash

    # Check if the hash matches either pattern
    if re.fullmatch(pattern1, hash):
        jerar.append("pbkdf2-sha1 (salted)")  # Base64 format match
    elif re.fullmatch(pattern2, hash):
        jerar.append("pbkdf2-sha1 (salted, hex format)")

def pbkdf2_sha512(hash, jerar):
    """Check if the hash is a PBKDF2-SHA512 hash."""
    
    # Regular expressions to check for PBKDF2-SHA512 formats
    # pattern1 = r'^\$pbkdf2-sha512\$(iterations=)?\d+\$(?:[a-zA-Z0-9+/=]{22,})\$(?:[a-f0-9]{128})$'  # Base64 format
    pattern1 = r'^pbkdf2_sha512\$\d+\$[a-zA-Z0-9+/]+(?:={0,2})?\$[a-zA-Z0-9+/]+(?:={0,2})?$'

    pattern2 = r'^[a-fA-F0-9]{128}$'  # Hexadecimal format, both salt and hash

    # Check if the hash matches either pattern
    if re.fullmatch(pattern1, hash):
        jerar.append("pbkdf2-sha512 (salted)")  # Base64 format match
    elif re.fullmatch(pattern2, hash):
        jerar.append("pbkdf2-sha512 (salted, hex format)")

        
# def pbkdf2_sha256(hash, jerar):
#     # Regular expression for detecting PBKDF2 hashes
#     if re.fullmatch(r'^\$pbkdf2-sha256\$(iterations=)?\d+\$(?:[a-zA-Z0-9+/=]{22,})\$(?:[a-f0-9]{64})$', hash):
#         jerar.append("pbkdf2-sha256 (salted)")

#         # Extract the salt from the hash (Base64 encoded)
#         salt = hash.split('$')[3]
        
#         # Handle missing padding in Base64 salt
#         padding_needed = len(salt) % 4
#         if padding_needed != 0:
#             salt += '=' * (4 - padding_needed)  # Add necessary padding
        
#         try:
#             # Try decoding the Base64 salt
#             decoded_salt = base64.b64decode(salt)
#             print(f"Decoded Salt: {decoded_salt.decode('utf-8')}")
#         except Exception as e:
#             print(f"Error decoding salt: {e}")

# def pbkdf2_sha256(hash, jerar):
#     """Check if the hash is a PBKDF2-SHA256 hash."""
#     # Regular expression to check if the hash matches PBKDF2-SHA256 format
#     pattern = r'^\$pbkdf2-sha256\$(iterations=)?\d+\$(?:[a-zA-Z0-9+/=]{22,})\$(?:[a-f0-9]{64})$'
#     check = bool(re.match(pattern, hash))
    
#     # If the hash matches, append to jerar list
#     if check:
#         jerar.append("pbkdf2-sha256 (salted)")





# def extract_salt(hash_str):
#     """Extracts the salt from an Argon2 hash if it matches the Argon2 format."""
#     # Pattern to match Argon2 encoded format and capture the salt
#     pattern = r'^\$argon2(?:i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$([A-Za-z0-9+/]+={0,2})\$[A-Za-z0-9+/]+={0,2}$'
#     match = re.match(pattern, hash_str)
    
#     if match:
#         salt = match.group(1)
#         return salt
#     else:
#         return None

def extract_salt(hash_str):
    """Extracts the salt from an Argon2 or PBKDF2-SHA256 hash."""
    
    # Pattern to match Argon2 encoded format and capture the salt
    argon2_pattern = r'^\$argon2(?:i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$([A-Za-z0-9+/]+={0,2})\$[A-Za-z0-9+/]+={0,2}$'
    
    # Match the Argon2 pattern
    match_argon2 = re.match(argon2_pattern, hash_str)
    if match_argon2:
        return match_argon2.group(1)
    else:
        return None

# Function to decode Base64 salt
def decode_base64_salt(salt_base64):
    """Decode a Base64 encoded salt and return the original string."""
    try:
        # Add padding if necessary
        padding = len(salt_base64) % 4
        if padding != 0:
            salt_base64 += '=' * (4 - padding)
        
        # Decode Base64 to get the original salt
        decoded_salt = base64.b64decode(salt_base64).decode('utf-8')
        return decoded_salt
    except Exception as e:
        return f"Error decoding salt: {str(e)}"
    


# Main execution
def main():
    print(logo)
    
    try:
        first = str(argv[1]) if len(argv) > 1 else None
    except IndexError:
        first = None

    while True:
        try:
            jerar = []  # Reset jerar for each input
            print("=" * 70)
            
            h = first if first else input("🔍 Enter Hash: ")

            # Run hash checks
            MD5(h, jerar)
            SHA1(h, jerar)
            SHA256(h, jerar)
            SHA512(h, jerar)
            CRC32(h, jerar)
            CRC32b(h,jerar)
            CRC32b_PHP(h, jerar)
            NTLM(h, jerar)
            CRC32_padded(h, jerar)
            MD4_T(h, jerar)
            SHA224(h, jerar)
            SHA384(h, jerar)
            SHA3_256(h, jerar)
            SHA3_512(h, jerar)
            Blake2b(h, jerar)
            RIPEMD160(h, jerar)
            Whirlpool(h, jerar)
            Adler32(h, jerar)
            FCS32(h, jerar)
            GHash32_3(h, jerar)
            GHash32_5(h, jerar)
            FNV132(h, jerar)
            Fletcher32(h, jerar)
            Joaat(h, jerar)
            ELF32(h, jerar)
            XOR32(h, jerar)
            Microsoft_Outlook_PST(h, jerar)
            Dahua(h, jerar)
            bcrypt(h, jerar)
            PBKDF2(h, jerar)
            argon2i(h, jerar)
            argon2d(h , jerar)
            argon2id(h , jerar)
            pbkdf2_sha256(h, jerar)
            pbkdf2_sha512(h, jerar)
            pbkdf2_sha1(h, jerar)
            # Add calls to other hash-check functions as needed

            print("=" * 70)    

            if len(jerar) == 0:
                print("🚫 Hash Type Not Found.")
            else:
                jerar.sort()
                print("\n🔑 Possible Hash Types:\n" + "-" * 24)
                
                # Print primary match if it exists
                for i in range(min(2, len(jerar))):
                    print(f"[+] {algorithms[jerar[i]]}")
                
                # Print additional less likely matches if they exist
                if len(jerar) > 2:
                    print("\n🔍 Additional Possible Matches:\n" + "-" * 29)
                    for i in range(2, len(jerar)):
                        print(f"[+] {algorithms[jerar[i]]}")
                
                for hash_type in jerar:
                    if "argon2" in algorithms[hash_type].lower():
                        print("\n🎯 Argon2 Hash Detected!")

                        # Extract and decode the salt from the Argon2 hash
                        salt_base64 = extract_salt(h)
                        if salt_base64:
                            decoded_salt = decode_base64_salt(salt_base64)
                            print(f"🎉 Salt Found and Decoded: {decoded_salt}")
                        else:
                            print("❌ No salt found in the Argon2 hash.")
                        break

                print("=" * 70)   
                
                print("\n🎉 Identification Complete!")
            
            first = None  # Reset first argument for the next loop
            print("=" * 70)

        except KeyboardInterrupt:
            print("\n\n\t👋 Exiting. Goodbye!")
            exit()

# Run main
if __name__ == "__main__":
    main()

