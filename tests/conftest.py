import ipaddress
import socket
import pytest

def check_local(address):
    if(not isinstance(address, tuple) or not address):
        raise AssertionError("External socket access blocked in tests")
    try:
        ip = ipaddress.ip_address(address[0])
    except (TypeError, ValueError):
        raise AssertionError("External name resolution blocked in tests") from None
    if(not ip.is_loopback):
        raise AssertionError("External socket access blocked in tests")

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex
    sendto = socket.socket.sendto
    getaddrinfo = socket.getaddrinfo
    def guarded_connect(sock, address):
        check_local(address)
        return connect(sock, address)
    def guarded_connect_ex(sock, address):
        check_local(address)
        return connect_ex(sock, address)
    def guarded_sendto(sock, data, *args):
        check_local(args[-1])
        return sendto(sock, data, *args)
    def guarded_lookup(host, port, *args, **kwargs):
        check_local((host, port))
        return getaddrinfo(host, port, *args, **kwargs)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_lookup)
