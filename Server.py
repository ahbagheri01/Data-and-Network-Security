import datetime
import json
import random
import socket
import ssl
import threading
from typing import List, Dict

import RSA
import SecureSocket
from Group import Group
from Message import Message
from User import User
from PrettyLogger import logger_config
import Resources

log = logger_config("webserver")
users: List[User] = []
groups: Dict[str, Group] = {}
messages: Dict[str, List[Message]] = {}
server_private_key = None


def receive_from_client(client_socket, user: User):
    response = client_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
    signature = response[-1]
    timestamp = response[-2]
    signed_message = Resources.SEP.join(response[:-1])
    original_message = Resources.SEP.join(response[:-2])

    Resources.verify_timestamp(timestamp)

    if user is not None:
        RSA.verify_signature(signed_message, signature, RSA.pem_to_public_key(user.rsa_pk))

    return original_message


def establish_https_connection() -> socket.socket:
    global server_private_key
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='./keys/certificate.pem', keyfile="./keys/key.pem")
    with open("./keys/key.pem") as f:
        server_private_key = RSA.pem_to_private_key(f.read())

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # This solves address already in use issue

    server_socket.bind(('localhost', 12346))
    server_socket.listen(5)

    log.info("Server is listening on localhost:12346")

    return server_socket


def response_client(client_socket: socket.socket, response):
    client_socket.send(response.encode("ASCII"))
    log.info(f"message to client: {response.encode('ASCII')}")


def username_exists(username: str) -> bool:
    for user in users:
        if user.username == username:
            return True
    for group_name in groups:
        if group_name == username:
            return True
    return False


def register_new_user(client_socket: socket.socket, username, password_hash, rsa_pk, elgamal_pk, prekey_pk):
    if username_exists(username):
        response = f"400{Resources.SEP}" \
                   f"Bad Request{Resources.SEP}" \
                   f"Username already exists"
        response_client(client_socket, response)
        return

    new_user = User(username, password_hash, rsa_pk, elgamal_pk, prekey_pk)
    users.append(new_user)
    messages[new_user.username] = []

    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"User registered successfully"
    response_client(client_socket, response)
    return new_user


def renew_keys(client_socket: socket.socket, user: User, old_password_hash, new_password_hash, rsa_pk, elgamal_pk,
               prekey_pk):
    if user.password_hash != old_password_hash:
        response = f"400{Resources.SEP}" \
                   f"Bad Request{Resources.SEP}" \
                   f"Wrong password"
        response_client(client_socket, response)

    user.password_hash = new_password_hash
    user.rsa_pk = rsa_pk
    user.elgamal_pk = elgamal_pk
    user.prekey_pk = prekey_pk

    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"Keys and password renewed successfully"
    response_client(client_socket, response)
    return


def login_user(client_socket: socket.socket, username):
    for user in users:
        if username == user.username:
            salt = random.randint(0, 10 ** 50)
            response = f"200{Resources.SEP}" \
                       f"OK{Resources.SEP}" \
                       f"{salt}"
            response_client(client_socket, response)
            otp = receive_from_client(client_socket, None)

            if user.check_password(str(salt), otp):
                response = f"200{Resources.SEP}" \
                           f"OK{Resources.SEP}" \
                           f"User {user.username} logged in " \
                           f"successfully"
                response_client(client_socket, response)
                user.set_online()
                return user

            else:
                response = f"400{Resources.SEP}" \
                           f"Bad Request{Resources.SEP}" \
                           f"Wrong password"
                response_client(client_socket, response)
                return None

    response = f"400{Resources.SEP}" \
               f"Bad Request{Resources.SEP}" \
               f"User does not exist"
    response_client(client_socket, response)
    return None


def logout_user(client_socket: socket.socket, user: User):
    user.set_offline()
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"Goodbye!"
    response_client(client_socket, response)
    return True


def show_users_list(client_socket: socket.socket):
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}"

    for user in users:
        response += f"- {user.username} ({'Online' if user.is_online else 'Offline'})\n"

    response_client(client_socket, response[:-1])
    return


def retrieve_keys(client_socket: socket.socket, username: str):
    for user in users:
        if user.username == username:
            response = f"200{Resources.SEP}" \
                       f"OK{Resources.SEP}"
            response += user.rsa_pk + Resources.SEP + str(user.elgamal_pk) + Resources.SEP + str(user.prekey_pk)
            response_client(client_socket, response)
            return

    response = f"404{Resources.SEP}" \
               f"Not Found{Resources.SEP}" \
               f"User does not exist."
    response_client(client_socket, response)
    return


def save_message(client_socket: socket.socket, message: str):
    _type, source_username, target_username, target_group, seq, signature, text = message. \
        split(Resources.SEP, maxsplit=7 - 1)
    message_obj = Message(message_type=_type,
                          source_username=source_username,
                          target_username=target_username,
                          target_group=target_group,
                          seq=seq,
                          signature=signature,
                          text=text)

    for user in users:
        if user.username == target_username:
            if message_obj.target_group != "":
                if message_obj.target_group not in groups:
                    response = f"404{Resources.SEP}" \
                               f"Not Found{Resources.SEP}" \
                               f"Group does not exist."
                    response_client(client_socket, response)
                    return
                elif message_obj.source_username not in groups[message_obj.target_group].usernames:
                    response = f"403{Resources.SEP}" \
                               f"Forbidden{Resources.SEP}" \
                               f"You are not a member of this group."
                    response_client(client_socket, response)
                    return

            messages[user.username].append(message_obj)

            response = f"200{Resources.SEP}" \
                       f"OK{Resources.SEP}" \
                       f"Message saved."
            response_client(client_socket, response)
            return

    response = f"404{Resources.SEP}" \
               f"Not Found{Resources.SEP}" \
               f"User does not exist."
    response_client(client_socket, response)
    return


def fetch_messages(client_socket: socket.socket, user: User):
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"{json.dumps([str(message) for message in messages[user.username]])}"
    response_client(client_socket, response)

    buffer = receive_from_client(client_socket, user)
    if buffer == "ack":
        messages[user.username] = []


def create_group(client_socket: socket.socket, user: User, group_name: str):
    if username_exists(group_name):
        response = f"400{Resources.SEP}" \
                   f"Bad Request{Resources.SEP}" \
                   f"Username already exists"
        response_client(client_socket, response)
        return

    group = Group(user.username, group_name)
    groups[group_name] = group
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"Group created successfully"
    response_client(client_socket, response)


def add_member_to_group(client_socket: socket.socket, user: User, group_name, new_member_username):
    # check if group exists
    if group_name not in groups:
        response = f"404{Resources.SEP}" \
                   f"Not Found{Resources.SEP}" \
                   f"Group does not exist."
        response_client(client_socket, response)
        return

    group = groups[group_name]

    # check if sender of add request is member of the group
    if user.username not in group.usernames:
        response = f"403{Resources.SEP}" \
                   f"Not Forbidden{Resources.SEP}" \
                   f"You are not a member of this group."
        response_client(client_socket, response)
        return

    # check if sender of add request is admin of the group
    if user.username != group.admin_username:
        response = f"403{Resources.SEP}" \
                   f"Not Forbidden{Resources.SEP}" \
                   f"You are not the admin of this group."
        response_client(client_socket, response)
        return

    # check if requested user exists
    if new_member_username not in [user.username for user in users]:
        response = f"404{Resources.SEP}" \
                   f"Not Found{Resources.SEP}" \
                   f"User does not exist."
        response_client(client_socket, response)
        return

    # check if requested user is already in the group
    if new_member_username in group.usernames:
        response = f"400{Resources.SEP}" \
                   f"Not Not Found{Resources.SEP}" \
                   f"User is already a member of this group."
        response_client(client_socket, response)
        return

    for old_member_username in group.usernames:
        # if old_member_username != user.username:
        add_text = new_member_username + Resources.SEP + group.group_name
        message_obj = Message(message_type="add",
                              source_username="",
                              target_username=old_member_username,
                              seq=0,
                              signature=RSA.sign(str(0) + add_text, server_private_key),
                              text=add_text)
        messages[old_member_username].append(message_obj)

    group.usernames.append(new_member_username)

    join_text = group.admin_username + Resources.SEP + group.group_name + Resources.SEP + json.dumps(group.usernames)
    message_obj = Message(message_type="join",
                          source_username="",
                          target_username=new_member_username,
                          seq=0,
                          signature=RSA.sign(str(0) + join_text, server_private_key),
                          text=join_text)
    messages[new_member_username].append(message_obj)

    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"User added to group successfully."
    response_client(client_socket, response)
    return


def remove_member_from_group(client_socket: socket.socket, user: User, group_name, to_be_removed_username):
    # check if group exists
    if group_name not in groups:
        response = f"404{Resources.SEP}" \
                   f"Not Found{Resources.SEP}" \
                   f"Group does not exist."
        response_client(client_socket, response)
        return

    group = groups[group_name]

    # check if sender of remove request is member of the group
    if user.username not in group.usernames:
        response = f"403{Resources.SEP}" \
                   f"Not Forbidden{Resources.SEP}" \
                   f"You are not a member of this group."
        response_client(client_socket, response)
        return

    # check if sender of remove request is admin of the group
    if user.username != group.admin_username:
        response = f"403{Resources.SEP}" \
                   f"Not Forbidden{Resources.SEP}" \
                   f"You are not the admin of this group."
        response_client(client_socket, response)
        return

    # check if requested user exists
    if to_be_removed_username not in [user.username for user in users]:
        response = f"404{Resources.SEP}" \
                   f"Not Found{Resources.SEP}" \
                   f"User does not exist."
        response_client(client_socket, response)
        return

    # check if requested user is already in the group
    if to_be_removed_username not in group.usernames:
        response = f"404{Resources.SEP}" \
                   f"Not Found{Resources.SEP}" \
                   f"User is not a member of this group."
        response_client(client_socket, response)
        return

    for member_username in group.usernames:
        # if member_username != user.username:
        remove_text = to_be_removed_username + Resources.SEP + group.group_name
        message_obj = Message(message_type="remove",
                              source_username="",
                              target_username=member_username,
                              seq=0,
                              signature=RSA.sign(str(0) + remove_text, server_private_key),
                              text=remove_text)
        messages[member_username].append(message_obj)

    group.usernames.remove(to_be_removed_username)

    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"User removed from group successfully."
    response_client(client_socket, response)
    return


def client_handler(client, address):
    log.info(f"Client with address {address} connected.")
    user = None

    try:
        while True:
            buffer = receive_from_client(client, user)
            log.info(f"message from client: {buffer.encode('ASCII')}")

            arr = buffer.split(Resources.SEP)

            if len(buffer) == 0:
                raise IndexError

            if arr[0] == "register":
                user = register_new_user(client, arr[1], arr[2], arr[3], arr[4], arr[5])
            elif arr[0] == "renew":
                renew_keys(client, user, arr[1], arr[2], arr[3], arr[4], arr[5])
            elif arr[0] == "show users list":
                show_users_list(client)
            elif arr[0] == "login":
                user = login_user(client, arr[1])
            elif arr[0] == "logout":
                if logout_user(client, user):
                    user = None
            elif arr[0] == "retrieve keys":
                retrieve_keys(client, arr[1])
            elif arr[0] == "x3dh":
                save_message(client, buffer)
            elif arr[0] == "text":
                save_message(client, buffer)
            elif arr[0] == "dr_pk":
                save_message(client, buffer)
            elif arr[0] == "group_text":
                save_message(client, buffer)
            elif arr[0] == "fetch":
                fetch_messages(client, user)
            elif arr[0] == "create":
                create_group(client, user, arr[1])
            elif arr[0] == "add":
                add_member_to_group(client, user, arr[1], arr[2])
            elif arr[0] == "remove":
                remove_member_from_group(client, user, arr[1], arr[2])

    except (KeyboardInterrupt, IndexError):
        client.close()
        if user is not None:
            user.set_offline()
        log.info(f"Client with address {address} disconnected.")


def https_client_handler(https_socket: socket.socket):
    try:
        while True:
            client, address = https_socket.accept()
            client = SecureSocket.wrap_socket(client)
            client.establish_server(server_private_key)
            handler_thread = threading.Thread(target=client_handler, args=(client, address))
            handler_thread.start()
    except KeyboardInterrupt:
        log.warning("terminating server")
        https_socket.close()


def main():
    https_socket = establish_https_connection()
    https_client_handler(https_socket)


if __name__ == "__main__":
    main()
