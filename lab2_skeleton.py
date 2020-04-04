# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import threading


class Constants:
    RQ_LEN = 3

    MAX_RECEIVE = 4096

    DECODE = 'unicode_escape'

    DEF_PORT: int = 80

    class Index:
        MVP = 0  # Method Path Version
        PHH = 1  # Port Headers Host

        METHOD = 0
        PATH = 1
        VERSION = 2

    class Attributes:
        HTTP = 'http'
        HTTP_V0 = HTTP + '/1.0'
        HTTP_V1 = HTTP + '/1.1'
        HOST = 'Host'

    class Delimiters:
        RQ_ENDING = '\r\n\r\n'
        RQ_LINES_DELIMITER = '\r\n'
        PATH = '/'
        HOST = ':'
        SPACE = ' '

    class Operations:
        INVALID_INPUT = {}
        GOOD = {'get'}
        NOT_SUPPORTED = {'put', 'post', 'delete', 'head'}
        PLACEHOLDER = {}

    class Responses:
        BAD = (400, 'Bad Request')
        NOT_SUPPORTED = (501, 'Not Supported')

        class Index(int):
            CODE = 0
            MSG = 1


class Cache:
    """
    Represents a Cache object that caches request so it can
    be handled later on and no data loss occurs
    """

    def __init__(self):
        self.__cache = dict()

    def check(self, response):
        if response.requested_host is not None and response.requested_path is not None:
            url = response.requested_host + response.requested_path
            if url in self.__cache.keys():
                return self.__cache[url]
        return None

    def cache(self, response, r):
        if response.requested_host is not None and response.requested_path is not None:
            self.__cache[response.requested_host + response.requested_path] = r


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        http = f'{self.method} {self.requested_path} ' \
               + Constants.Attributes.HTTP_V0.upper() \
               + Constants.Delimiters.RQ_LINES_DELIMITER
        for h in self.headers:
            http += f'{h[0]}: {h[1]}' + Constants.Delimiters.RQ_LINES_DELIMITER
        return http + Constants.Delimiters.RQ_LINES_DELIMITER

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, 'UTF-8')

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        return f'[{str.upper(self.message)}: {self.code}] '

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, 'UTF-8')

    def display(self):
        print(self.to_http_string())


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """
    start(setup_sockets(proxy_port_number))


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.

    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind(('localhost', proxy_port_number))
    proxy_socket.listen(20)
    return proxy_socket


def start(proxy_socket: socket):
    cache = Cache()
    try:
        while True:
            client, address = proxy_socket.accept()
            threading.Thread(target=client_handler, args=(client, address, cache)).start()
    except KeyboardInterrupt:
        proxy_socket.close()


def client_handler(client: socket, address, c: Cache):
    proxy_response = http_request_pipeline(address, receive_client_request(client))
    if isinstance(proxy_response, HttpErrorResponse):
        client.sendto(proxy_response.to_byte_array(proxy_response.to_http_string()), address)
    else:
        response = c.check(proxy_response)
        if response is None:
            response = server_handler(proxy_response)
            c.cache(proxy_response, response)
        if response is not None:
            for proxy_response in response:
                client.sendto(proxy_response, address)
    client.close()


def receive_client_request(s: socket) -> str:
    request = ""
    while request.find(Constants.Delimiters.RQ_ENDING) == -1:
        request += http_request_decode(s.recv(Constants.MAX_RECEIVE))
    return request


def server_handler(response: HttpRequestInfo):
    server_socket = setup_server_socket(response)
    if server_socket is None:
        return
    return receive_server_response(server_socket, response)


def setup_server_socket(response: HttpRequestInfo) -> socket:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ip = socket.gethostbyname(response.requested_host)
    except TypeError or TimeoutError:
        return None
    server_socket.connect((ip, response.requested_port))
    return server_socket


def receive_server_response(s: socket, response: HttpRequestInfo) -> list:
    s.send(response.to_byte_array(response.to_http_string()))
    received_data = s.recv(Constants.MAX_RECEIVE)
    server_response = []
    while len(received_data) > 0:
        server_response.append(received_data)
        received_data = s.recv(Constants.MAX_RECEIVE)
    s.close()
    return server_response


def generate_error(state: HttpRequestState) -> HttpErrorResponse:
    return {
        HttpRequestState.INVALID_INPUT: HttpErrorResponse(
            Constants.Responses.BAD[Constants.Responses.Index.CODE],
            Constants.Responses.BAD[Constants.Responses.Index.MSG])
    }.get(state, HttpErrorResponse(Constants.Responses.NOT_SUPPORTED[Constants.Responses.Index.CODE],
                                   Constants.Responses.NOT_SUPPORTED[Constants.Responses.Index.MSG]))


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    state = check_http_request_validity(http_raw_data)
    if state is not HttpRequestState.GOOD:
        return generate_error(state)
    return sanitize_http_request(parse_http_request(source_addr, http_raw_data))


def http_request_decode(http_raw_data: bytearray) -> str:
    return http_raw_data.decode(Constants.DECODE)


def parse_http_request(source_addr, http_raw_data: str) -> HttpRequestInfo:
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    request = parse_request(http_raw_data)

    method, requested_path, version = parse_MVP(request)
    requested_port, headers, requested_host = parse_PHH(request)

    return HttpRequestInfo(source_addr, method.upper(), requested_host, requested_port, requested_path.strip(), headers)


def parse_request(request: str) -> list:
    return list(filter(None, request.split(Constants.Delimiters.RQ_LINES_DELIMITER)))


def parse_MVP(request):
    mpv = request[Constants.Index.MVP].split(Constants.Delimiters.SPACE)
    if mpv.__len__() != Constants.RQ_LEN:
        print('[ERROR] Request length does not match.')
        print(f'[VERBOSE] Expected 3 args but got {mpv.__len__()} instead.')
        exit(-1)
        return
    return mpv


def parse_PHH(request):
    phh = request[Constants.Index.PHH:]

    port: int = Constants.DEF_PORT
    headers: list = []
    host = None

    for attribute in phh:
        h = parse_header(attribute)
        headers.append(h)
        if h[0] == Constants.Attributes.HOST:
            host, port = parse_host_port(h)
    return port, headers, host


def parse_header(header) -> list:
    h: list = header.split(Constants.Delimiters.HOST)
    h = [i.strip() if type(i) == str else str(i) for i in h]
    return h


def parse_host_port(header: list):
    hp: list = header[1].split(Constants.Delimiters.HOST)
    return hp[0], (int(hp[1]) if len(hp) > 2 else Constants.DEF_PORT)


def split_http_request(http_request: str):
    try:
        headers = http_request.split(Constants.Delimiters.RQ_LINES_DELIMITER)[Constants.Index.PATH:]
        method = http_request.split(Constants.Delimiters.SPACE)[Constants.Index.METHOD]
        path = http_request.split(Constants.Delimiters.SPACE)[Constants.Index.PATH]
        version = http_request.split(Constants.Delimiters.SPACE)[Constants.Index.VERSION]
    except ValueError or IndexError:
        exit(-1)
        return
    return headers, method, path, version


def format_http_raw_data(http_raw_data: str) -> str:
    return http_raw_data.lower()


def check_http_request_validity(http_raw_data: str) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """
    http_request = format_http_raw_data(http_raw_data)

    state = check_request_line_validity(http_request.split("\r\n")[0])
    if state != HttpRequestState.GOOD:
        return state

    headers, method, path, version = split_http_request(format_http_raw_data(http_raw_data))

    state = check_request_ending_validity(http_raw_data)
    if state != HttpRequestState.GOOD:
        return state
    state = check_headers_validity(headers)
    if state != HttpRequestState.GOOD:
        return state
    state = check_host_validity(path, headers)
    if state != HttpRequestState.GOOD:
        return state
    state = check_version_validity(version)
    if state != HttpRequestState.GOOD:
        return state
    state = check_method_validity(method)
    if state != HttpRequestState.GOOD:
        return state
    return HttpRequestState.GOOD


def check_request_line_validity(request: str) -> HttpRequestState:
    if request is None \
            or not request.strip() \
            or len(request.split(Constants.Delimiters.SPACE)) != Constants.RQ_LEN:
        return HttpRequestState.INVALID_INPUT
    return HttpRequestState.GOOD


def check_request_ending_validity(string: str) -> HttpRequestState:
    return HttpRequestState.INVALID_INPUT \
        if string[-Constants.Delimiters.RQ_ENDING.__len__():] != Constants.Delimiters.RQ_ENDING \
        else HttpRequestState.GOOD


def check_method_validity(method: str) -> HttpRequestState:
    if method in Constants.Operations.GOOD:
        return HttpRequestState.GOOD
    elif method in Constants.Operations.NOT_SUPPORTED:
        return HttpRequestState.NOT_SUPPORTED
    elif method in Constants.Operations.PLACEHOLDER:
        return HttpRequestState.PLACEHOLDER
    return HttpRequestState.INVALID_INPUT


def check_headers_validity(headers: list) -> HttpRequestState:
    return HttpRequestState.INVALID_INPUT if headers is None else HttpRequestState.GOOD


def check_version_validity(version: str) -> HttpRequestState:
    v = version.strip()[:version.find(Constants.Delimiters.RQ_LINES_DELIMITER)]
    return HttpRequestState.INVALID_INPUT \
        if v != Constants.Attributes.HTTP_V0 and v != Constants.Attributes.HTTP_V1 \
        else HttpRequestState.GOOD


def check_host_validity(path: str, headers: list) -> HttpRequestState:
    def check_all_hosts_validity(hds: list) -> bool:
        for h in hds:
            line = h.split(Constants.Delimiters.HOST)
            if line[0].strip() == Constants.Attributes.HOST.lower():
                return True
        return False

    valid_host = True
    if path.startswith(Constants.Delimiters.PATH):
        valid_host = check_all_hosts_validity(headers)
    return HttpRequestState.GOOD if valid_host else HttpRequestState.INVALID_INPUT


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.

    returns:
    nothing, but modifies the input object
    """
    path = request_info.requested_path

    if path.__contains__(Constants.Attributes.HTTP):
        start_index, end_index = get_sanitization_indices(path)
        host = path[start_index:end_index]

        request_info.requested_path = sanitize_path(path[end_index:])

        if host.__contains__(Constants.Delimiters.HOST):
            host, port = sanitize_host_port(host)
            request_info.requested_port = port

        if request_info.requested_host is None:
            request_info.headers.insert(0, (Constants.Attributes.HOST, host))
            request_info.requested_host = host

    return request_info


def sanitize_host_port(path):
    element = list(filter(None, path.split(Constants.Delimiters.HOST)))
    return element[0], int(element[1])


def sanitize_path(path):
    if not path:
        return Constants.Delimiters.PATH
    return path


def get_sanitization_indices(path: str):
    end_index = path.find(Constants.Delimiters.PATH, 8)
    start_index = path.find(Constants.Delimiters.PATH * 2) + 2
    return start_index, end_index


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
