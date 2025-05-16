import hashpumpy
import hashlib
import hmac
from urllib.parse import quote

# Server's verify function (copied for testing)
SECRET_KEY = b'supersecretkey'  # For testing; attacker doesn't know this

def generate_mac(message: bytes) -> str:
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    expected_mac = generate_mac(message)
    return hmac.compare_digest(mac.encode(), expected_mac.encode())

def perform_attack():
    print("\n=== LENGTH EXTENSION ATTACK DEMO ===")
    print("Demonstrating why hash(secret||message) is vulnerable")
    
    # Intercepted values
    intercepted_message = b"amount=100&to=alice"
    intercepted_mac = input("Enter intercepted MAC from server.py: ").strip()
    data_to_append = b"&admin=true"

    print("\nAttempting attack with key length guess: 14 bytes")
    
    try:
        new_mac, new_message = hashpumpy.hashpump(
            intercepted_mac,
            intercepted_message,
            data_to_append,
            14  # Correct length for 'supersecretkey'
        )
    except Exception as e:
        print("Error:", e)
        print("Ensure hashpumpy is installed (pip install hashpumpy)")
        return

    print("Original message:", intercepted_message.decode())
    print("Original MAC:", intercepted_mac)
    print("\nForged message:", quote(new_message.decode('latin1')))
    print("Forged MAC:", new_mac)

    # Verify the attack
    if verify(new_message, new_mac):
        print("\nServer accepted forged message!")
        print("This proves the MAC implementation is vulnerable")
    else:
        print("\nAttack failed (unexpected)")

if __name__ == "__main__":
    perform_attack()