import hashlib

SECRET_KEY = b'supersecretkey'  # Unknown to attacker

def generate_mac(message: bytes) -> str:
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    expected_mac = generate_mac(message)
    return mac == expected_mac

def main():
    # Example message
    message = b"amount=100&to=alice"
    mac = generate_mac(message)
    print("=== Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"Original MAC: {mac}")
    print("\n----Verifying legitimate message----")
    if verify(message, mac):
        print("MAC verified successfully. Message is authentic.")
    else:
        print("MAC verification failed.")

    # Simulated attacker-forged message (from client.py output)

    forged_message = b"amount=100&to=alice" + b"&admin=true"
    #forged_message = b'amount=100&to=alice\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00&admin=true'
    
    forged_mac = mac
    #forged_mac = "97312a73075b6e1589117ce55e0a3ca6"
    
    print("\n----Verifying forged message----")
    print(f"Forged message: {forged_message.decode('latin-1')}")
    print(f"Forged MAC: {forged_mac}")
    if verify(forged_message, forged_mac):
        print("MAC verified successfully (UNEXPECTED - VULNERABLE)")
    else:
        print("MAC verification failed (EXPECTED - SECURE)")

if __name__ == "__main__":
    main()