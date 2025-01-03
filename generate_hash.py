from web3 import Web3

# Example data
service = "example_service"
username = "example_user"
password = "example_password"

# Generate a hash using keccak256 (Ethereum's hashing algorithm)
credential_hash = Web3.keccak(text=f"{service}:{username}:{password}").hex()

print(credential_hash)  # This is the hash string you will input into the storeHash function