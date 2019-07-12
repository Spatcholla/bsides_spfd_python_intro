import asyncio
import ipaddress
import re
import sys
from typing import Generator, NamedTuple, Tuple, Any

# pip dependencies
from aiostream.stream import merge

MAX_CONCURRENCY = 200


class PortScanTask(NamedTuple):
    ip: str
    port: int
    timeout: float


def ip_sort(t: PortScanTask):
    """used to sort output by ipaddress, then port"""
    return tuple([*map(int, t.ip.split('.')), t.port])


def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def parse_ports(port_string):
    """
        syntax: port,port-range,...
        use regex to verify input validity, then create a tuple of
        ports used in port scan. there definitely some room for optimization
        here, but it won't matter much. go optimize the coroutines instead.
    """
    if not re.match(r'[\d\-,\s]+', port_string):
        raise ValueError('Invalid port string')
    ports = []
    port_string = list(filter(None, port_string.split(',')))
    for port in port_string:
        if '-' in port:
            try:
                port = [int(p) for p in port.split('-')]
            except ValueError:
                raise ValueError('Are you trying to scan a negative port?')
            for p in range(port[0], port[1] + 1):
                ports.append(p)
        else:
            ports.append(int(port))
    for port in ports:
        if not (-1 < port < 65536):
            raise ValueError('Ports must be between 0 and 65535')
    return tuple(set(ports))


def fancy_print(data, csv):
    if csv:
        fmt = '{},{}'
    else:
        fmt = '{:<15} :{}'
    for datum in data:
        print(fmt.format(*datum))


async def task_worker(task_generator: Generator[PortScanTask, Any, None]):
    """pull connection information from queue and attempt connection"""
    while True:
        try:
            task: PortScanTask = next(task_generator)
        except StopIteration:
            # Generator is exhausted. Stop scanning
            return

        conn = asyncio.open_connection(task.ip, task.port)
        try:
            await asyncio.wait_for(conn, task.timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError):
            pass
        else:
            yield task  # yield successful tasks


def task_generator(network: str, port_range: Tuple[int], timeout: float):
    """add jobs to a queue, up to ``MAX_NUMBER_WORKERS'' at a time"""
    network = network.replace('/32', '')
    try:
        # check to see if we are scanning a single host...
        hosts = [str(ipaddress.ip_address(network)), ]
    except ValueError:
        # ...or a CIDR subnet.
        hosts = map(str, ipaddress.ip_network(network).hosts())
    for ip in hosts:
        eprint(ip)
        for port in port_range:
            yield PortScanTask(ip, port, timeout)


async def scanner(network, ports=None, timeout=0.1, csv=False):
    """
        main task coroutine which manages all the other functions
        if scanning over the internet, you might want to set the timeout
        to around 1 second, depending on internet speed.
    """
    scan_completed = asyncio.Event()
    scan_completed.clear()  # progress the main loop

    if ports is None:  # list of common-ass ports
        ports = ("9,20-23,25,37,41,42,53,67-70,79-82,88,101,102,107,109-111,"
                 "113,115,117-119,123,135,137-139,143,152,153,156,158,161,162,170,179,"
                 "194,201,209,213,218,220,259,264,311,318,323,383,366,369,371,384,387,"
                 "389,401,411,427,443-445,464,465,500,512,512,513,513-515,517,518,520,"
                 "513,524,525,530,531,532,533,540,542,543,544,546,547,548,550,554,556,"
                 "560,561,563,587,591,593,604,631,636,639,646,647,648,652,654,665,666,"
                 "674,691,692,695,698,699,700,701,702,706,711,712,720,749,750,782,829,"
                 "860,873,901,902,911,981,989,990,991,992,993,995,8080,2222,4444,1234,"
                 "12345,54321,2020,2121,2525,65535,666,1337,31337,8181,6969")
    ports = parse_ports(ports)

    # initialize task generator
    task_gen = task_generator(network, ports, timeout)

    open_ports = list()
    eprint('scanning . . .')
    workers = [task_worker(task_gen) for _ in range(MAX_CONCURRENCY)]
    merged = merge(*workers)
    async with merged.stream() as streamer:
        async for task in streamer:
            open_ports.append(task)

    eprint('gathering output . . .')
    open_ports.sort(key=ip_sort)
    fancy_print(open_ports, csv=csv)

    eprint('shutting down . . .')


if __name__ == '__main__':
    # import argparse?
    if len(sys.argv) < 2:
        print(
            'TCP Network scanner using asyncio module for Python 3.7+',
            "Scan ports in ``portstring'' or common ports if blank."
            'Port string syntax: port, port-range ...',
            f'Usage: {sys.argv[0]} network [portstring]',
            sep='\n'
        )
        raise SystemExit
    elif len(sys.argv) == 2:
        asyncio.run(scanner(sys.argv[1]))
    else:
        asyncio.run(scanner(sys.argv[1], ''.join(sys.argv[2:])))
