import pyshark
import re

GREASE_CODES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

def parse_ciphersuites(packet: pyshark.packet.packet.Packet):
    """
    Parses Cipher Suite hex values from a ClientHello packet. 
    It filters out relevant GREASE values. 
    
    Args: 
        packet: (pyshark.packet.packet.Packet): pyshark ClientHello packet

    Returns:
        List[int]: sorted list of cipher suite hex values
    """
        
    # retrieve the hex value of ciphersuite values
    clean_hex_values = []
    
    for field in packet.tls.handshake_ciphersuite.all_fields:
        hex_value = field.hex_value
        if hex_value not in GREASE_CODES:
            clean_hex_values.append(hex(hex_value))    
    
    # clean_hex_values.sort()
    return clean_hex_values

def parse_extensions(packet: pyshark.packet.packet.Packet):
    """
    Parses extension hex values from a ClientHello packet. 
    It filters out relevant GREASE values. 
    
    Args: 
        packet: (pyshark.packet.packet.Packet): pyshark ClientHello packet

    Returns:
        List[int]: sorted list of extension hex values
    """
    tls_fields = packet.tls
    
    ja3 = tls_fields.get("tls.handshake.ja3_full", None)
    if not ja3:
        return []

    # ja3 might look like:
    #   '771,4867-4866-4865-...,43-51-0-11-10-13-16,29-23-24-25,0'
    # Split by commas
    parts = ja3.split(',')
    if len(parts) < 3:
        # If it doesn't have at least 3 sections, we can't parse
        return []

    # The third part is the 'Extensions' list in decimal, e.g. '43-51-0-11-10-13-16'
    extensions_part = parts[2]  # index 2 = 3rd field

    # Split that on dashes
    extension_ids_str = extensions_part.split('-')

    # Convert them to integers (decimal), then optionally to hex
    extension_ids = []
    for eid_str in extension_ids_str:
        if eid_str.strip():  # skip empty
            try:
                dec_val = int(eid_str)
                extension_ids.append(dec_val)
            except ValueError:
                pass  # skip non-numeric

    # If you'd like them in hex, convert after
    extension_ids_hex = [f"0x{val:04x}" for val in extension_ids]

    return extension_ids_hex
    
def parse_ja3_full(packet: str) -> dict:
    """
    Parse a JA3 Full string of the form:
      {Version},{Ciphers},{Extensions},{EllipticCurves},{ECPointFormats}
    
    Returns a dict with keys:
      - "version" (int)
      - "ciphers" (list[int])
      - "extensions" (list[int])
      - "elliptic_curves" (list[int])
      - "ec_point_formats" (list[int])
    If any field is missing or shorter than expected, empty lists or None are used.
    """
    
    tls_fields = packet.tls
    
    ja3_full = tls_fields.get("tls.handshake.ja3_full", None)
    # Split by comma
    parts = ja3_full.split(',')
    # We expect at least 5 parts in a typical JA3 Full
    # parts[0]: version (decimal)
    # parts[1]: ciphers (dash-separated)
    # parts[2]: extensions (dash-separated)
    # parts[3]: elliptic curves (dash-separated)
    # parts[4]: ec point formats (dash-separated)
    if len(parts) < 5:
        return {
            "version": None,
            "ciphers": [],
            "extensions": [],
            "elliptic_curves": [],
            "ec_point_formats": []
        }

    # Parse each comma-separated part
    version_str = parts[0].strip()
    ciphers_str = parts[1].strip()
    exts_str    = parts[2].strip()
    curves_str  = parts[3].strip()
    ecf_str     = parts[4].strip()

    # 1) Convert version to int
    try:
        version = int(version_str)
    except ValueError:
        version = None

    # 2) Convert ciphers to a list of int
    ciphers = []
    if ciphers_str:
        for c in ciphers_str.split('-'):
            c = c.strip()
            if c:
                try:
                    ciphers.append(int(c))
                except ValueError:
                    pass

    # 3) Convert extensions
    extensions = []
    if exts_str:
        for e in exts_str.split('-'):
            e = e.strip()
            if e:
                try:
                    extensions.append(int(e))
                except ValueError:
                    pass

    # 4) Convert elliptic curves
    elliptic_curves = []
    if curves_str:
        for g in curves_str.split('-'):
            g = g.strip()
            if g:
                try:
                    elliptic_curves.append(int(g))
                except ValueError:
                    pass

    # 5) Convert ec point formats
    ec_point_formats = []
    if ecf_str:
        for f in ecf_str.split('-'):
            f = f.strip()
            if f:
                try:
                    ec_point_formats.append(int(f))
                except ValueError:
                    pass

    return {
        "version": version,
        "ciphers": ciphers,
        "extensions": extensions,
        "elliptic_curves": elliptic_curves,
        "ec_point_formats": ec_point_formats
    }

def parse_signature_algs_from_ja4_r(packet: pyshark.packet.packet.Packet):
    """
    Some versions of 'ja4_r' might look like:
      t13d4907h2_0004,0005,000a,0016,002f,0033_0806,0601,0603,0805,...
    We can split by underscores '_' to isolate ciphers vs. signature algs, etc.
    The last portion might be signature alg codes in decimal or hex.
    """
    # Example: "t13d4907h2_0004,0005,000a,0016_0806,0601,0603"
    # We'll guess the signature alg part is after the second underscore.
    
    ja4_r_str = packet.tls.get('tls.handshake.ja4_r', None)    
    
    # Split into underscore-separated sections
    parts = ja4_r_str.split('_')
    if len(parts) < 4:
        # If we don't have at least 4 sections, we can't parse signature algs
        return []

    # The last part typically has the signature algorithm codes, e.g. "0806,0601,0603,0805, ..."
    sigalg_section = parts[-1]  # or parts[3] if you want to be explicit

    # Split that section on commas
    raw_codes = sigalg_section.split(',')

    # Create a list of "0xXXXX" strings in the order they appear
    signature_algs = [f"0x{code.strip().lower()}" for code in raw_codes if code.strip()]

    return signature_algs

def get_alpn_pyshark(packet):
    """
    Returns a list of ALPN protocols if PyShark exposes them 
    in 'handshake_extensions_alpn_str'.
    """
    if not hasattr(packet, 'tls'):
        return []

    tls_layer = packet.tls
    # This field often contains a single string with all protocols, 
    # e.g. "h2;http/1.1", or just "h2" if there's only one.
    alpn_str = getattr(tls_layer, 'handshake_extensions_alpn_str', None)
    if not alpn_str:
        return []

    # If multiple protocols are offered, PyShark might combine them in 
    # a semicolon- or comma-separated string. We can split them:
    # If you see they're separated by semicolons, do:
    protocols = [p.strip() for p in alpn_str.replace(',', ';').split(';')]
    return protocols


if __name__ == "__main__":
    capture = pyshark.LiveCapture(interface='lo0', display_filter="tls.handshake.type==1 && not quic")
    
    print("Listening for TLS ClientHello packets... Press Ctrl+C to stop.")
    try:
        for packet in capture.sniff_continuously():
            # Check if there's a TLS layer
            tls_layer = getattr(packet, 'tls', None)
            if tls_layer:
                print("===== Found TLS ClientHello Packet =====")
                print(tls_layer)  
                print("========================================\n")
            
            # cipher_suite_hex_values = parse_ciphersuites(packet)
            # print(f"Cipher Suite Values:\n{cipher_suite_hex_values}")
            # print("========================================\n")

            ja3_dict = parse_ja3_full(packet)
                
            print("Version:" + str(ja3_dict["version"]))          
            print("Ciphers: " + str(ja3_dict["ciphers"]))            
            print("Extensions: " + str(ja3_dict["extensions"]))            
            print("Elliptic curves / supported group: " + str(ja3_dict["elliptic_curves"]))          
            print("Ec point formats: " + str(ja3_dict["ec_point_formats"]))    
            print("Signature Algorithms: " + str(parse_signature_algs_from_ja4_r(packet)))
            print("ALPN Protocol: " + str(get_alpn_pyshark(packet)))

            print("========================================\n")
            

    except KeyboardInterrupt:
        print("Capture stopped by user.")  
        
    