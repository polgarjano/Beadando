from passlib.hash import bcrypt
from user_managment.app_regexps import PASSWORD_REGEXP
import re
from user_managment.app_transaction import AppTransaction
from user_managment.System_data import System_data
from user_managment.Permissions import Permissions


def register_user(transaction: AppTransaction, username, password, permissions, user_data):
    pipe = transaction.pipe
    transaction.append_before_multi((user_before, (password, pipe, username), {}))
    transaction.append_after_multi((user_after, (password, permissions, pipe, user_data, username), {}))


def reg_user(pipe, username, password, permissions, user_data):
    return [[(user_before, (password, pipe, username), {})],
            [(user_after, (password, permissions, pipe, user_data, username), {})]]


def user_after(password, permissions, pipe, user_data, username):
    hashed_password = bcrypt.hash(password)
    pipe.hset(username, "password", hashed_password)
    for p in permissions:
        pipe.hset(username, p, 1)
    for k in user_data.keys():
        pipe.hset(username, k, user_data[k])


def user_before(password, pipe, username):
    if not bool(re.match(PASSWORD_REGEXP, password)):
        return 'Password to weak', 400
    pipe.watch(username)
    if pipe.hexists(username, "password"):
        return 'Username already exists', 409
    return


def register_entyty(transaction: AppTransaction, name, data={}, message="entyty name already exists"):
    pipe = transaction.pipe

    transaction.append_before_multi((entyty_before, (name, pipe, message), {}))
    transaction.append_after_multi((entyty_after, (data, name, pipe), {}))


def reg_entyty(pipe, name, data={}, message="entyty name already exists"):
    return [[(entyty_before, (name, pipe, message), {})],
            [(entyty_after, (data, name, pipe), {})]]


def entyty_after(data, name, pipe):
    for k in data.keys():
        pipe.hset(name, k, data[k])


def entyty_before(name, pipe, message):
    pipe.watch(name)
    if pipe.exists(name):
        return message, 409
    return


def authorization(red, username, permissions, ticket):
    keys = [System_data.SESSION.value] + permissions
    user_data = red.hmget(username, keys)
    user_data = {keys[i]: user_data[i].decode() for i in range(len(user_data)) if user_data[i] != None}
    if not (System_data.SESSION.value in user_data.keys() and user_data[System_data.SESSION.value] == ticket):
        return False

    for p in permissions:
        if not (p in user_data.keys() and user_data[p] == '1'):
            return False

    return True


def login(red, username, password, token_generator, args, kwargs):
    permission = red.hget(username, Permissions.USER.value)
    if permission is None or not permission.decode() == '1':
        return False, ''

    stored_hashed_password = red.hget(username, System_data.PASSWORD.value).decode()
    if not bcrypt.verify(password, stored_hashed_password):
        return False, ''

    token = token_generator(*args, **kwargs)

    red.hset(username, "session", token)
    return True, token


def logout(red, username):
    red.hdel(username, System_data.SESSION.value)


if __name__ == '__main__':
    pass
