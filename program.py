"""This is the example module.

This module does stuff.
"""

__version__ = '0.1'
__author__ = 'Spatcholla'

import asyncio
import time

from async_tcp_scan import scanner


def print_header():
    title = "ASYNC TCP SCANNER"
    print('-' * 45)
    print(f'{title:^45}')
    print('-' * 45)
    print()


def program_loop():
    while True:
        cmd = input("Would you like to perform a [s]can or e[x]it?\n:: ").lower()
        if cmd == 's':
            ip_addr = input(
                "Enter the IP address or network CIDR you would like to scan: \n"
                "Example of accepted inputs: 192.168.50.54 or 172.16.20.128/25\n"
                ":: "
            )
            port = input(
                "Enter the port(s) you would like to scan; press enter to scan common ports:\n"
                "Example of accepted input: 22 or 9000-18000\n"
                ":: "
            )
            port = port if port is not '' else None

            asyncio.run(scanner(network=ip_addr, ports=port))
            time.sleep(1)
        else:
            print("Okay, exiting scanner... good bye!")
            break

        print()


def main():
    print_header()
    program_loop()


if __name__ == '__main__':
    main()
