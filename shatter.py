"""shattercrypt.

File fragmentation tool that will split ("shatter") a file in to variable smaller files ("shards"),
scattered in a given directory.
"""


import argparse
import os
import logging
import random
import tempfile
import string
import math
import hashlib
import base64
import getpass
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# You should change this value .. generate by
# os.urandom(16)
SALT = b'\x8d\xa1U\x9e|\xc0\xbc\xea\xa1\x02\x95W\x0e\x8f8\xbf'

logging.basicConfig(
    encoding='utf-8',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %I:%M:%S'
)

log = logging.getLogger()


def key_from_password(password):
    """Generate a Fernet key derived from password.

    Args:
        password (string): Password to generate a key for

    Returns:
        string: base64 encoded Fernet key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def float_range(start, stop, step):
    """Generate a range, but for floats.

    Args:
        start (float): number to start at
        stop (float): number to stop at
        step (float): how much to increment each number

    Yields:
        list: List of numbers between start/stop by step
    """
    while start < stop:
        yield float(start)
        start = start + step


class Reconstruct:
    """Reconstruct a file from a given shard."""

    def __init__(self, file, outfile, key):
        """Initialize some basic parameters."""
        self.given_file = file
        self.outfile = outfile
        self.fernet = Fernet(key)
        self.shards = {}
        self.shard_data = {}

        log.info("Retrieving shard headers")
        self.parse_header(file.name)

        shard = self.shards[self.given_file.name]
        self.first_shard = None

        # First work backward in the chain and get shards
        while 'prev_shard' in shard:
            self.parse_header(shard['prev_shard'])
            shard = self.shards[shard['prev_shard']]

        first_shard = shard
        log.debug(f"Found initial shard: {first_shard}")

        # Now work forward from the original file and get shards
        shard = self.shards[self.given_file.name]
        while 'next_shard' in shard:
            self.parse_header(shard['next_shard'])
            shard = self.shards[shard['next_shard']]

        log.debug(f"Got shards: {self.shards}")

        # Now we can iterate through our shard directory to reconstruct the original file
        self.outfh = open(outfile.name, 'wb')
        shard = first_shard
        while shard:
            shard = self.reconstruct_data(shard)
        self.outfh.close()

    def reconstruct_data(self, shard_directory):
        """Read, decrypt, and reconstruct shard data.

        Args:
            shard_directory (dict): Dictionary of a shard's directory

        Returns:
            [dict]: Directory dictionary for the next shard in the chain
        """
        log.debug(f"Reconstructing shard: {shard_directory}")
        directory_len = b''
        with open(shard_directory['filename'], 'rb') as shard:
            # Read through the header
            while True:
                data = shard.read(1)
                if data == b'\x00':
                    break
                directory_len = directory_len + data

            directory_len = int.from_bytes(directory_len, byteorder='little')

            # Skip over the header
            shard.read(directory_len)

            # Now read the data and write it out
            shard_data = base64.urlsafe_b64encode(shard.read())
            shard_data = self.fernet.decrypt(shard_data)

            self.outfh.write(shard_data)
            shard.close()

        return self.shards.get(shard_directory.get('next_shard', None), None)

    def parse_header(self, shard):
        """Parse a shard's header.

        Args:
            file (File): file to parse
        """
        log.info(f"Reading shard {shard}")

        directory_len = b''
        with open(shard, 'rb') as file:
            while True:
                data = file.read(1)
                if data == b'\x00':
                    break
                directory_len = directory_len + data

            directory_len = int.from_bytes(directory_len, byteorder='little')
            log.debug(f"Got directory length of {directory_len}")

            directory = base64.urlsafe_b64encode(file.read(directory_len))
            directory = self.fernet.decrypt(directory)
            log.debug(f"Got directory: {directory}")

            self.shards[shard] = json.loads(directory)

            file.close()


class Shatter:
    """Shatter a given file."""

    def __init__(self, file, key, **kwargs):
        """Initialize some basic parameters."""
        self.file = file
        self.file_size = os.path.getsize(file.name)
        self.fernet = Fernet(key)
        self.chunks = []
        self.shards = []
        self.shard_data = []

        log.debug(f"File size: {self.file_size}")

        # Decide which method to create chunk sizes based on file size and specified parameters
        if self.file_size <= 1:
            log.warning(f"Looks like this file is too small to actually split: {self.file_size} bytes.")
        elif self.file_size <= 10:
            pass
        else:
            self.split_by_fuzzy_chunks(shards=kwargs['shards'], fuzz_range=kwargs['fuzz_range'])

        # Now we can shatter the file and write out new files
        self.shatter()

    def split_by_fuzzy_chunks(self, shards=10, fuzz_range=0.5):
        """Calculate chunks based on file size that are broken up into roughly the number of chunks.

        Args:
            chunks (int, optional): Rough number of chunks to generate. Defaults to 10.
            fuzz_range (float, optional): Precentage (0.0-1.0) range to use for a random chunk size for each chunk. Defaults to 0.5.
        """
        log.info(f"Calculating fuzzy chunks for {self.file.name}")
        if shards >= self.file_size:
            log.warning(f"You specified more chunks than the bytes in the file")

        # For each chunk, calculate a ceiling (the file size divided by rough number of chunks)
        # and a floor (ceiling * fuzz_range%) to use as a range for choosing a random-ish chunk size
        rough_chunk_ceiling = math.ceil(self.file_size / shards)
        rough_chunk_floor = int(math.floor(rough_chunk_ceiling * fuzz_range))

        bytes_left = self.file_size
        self.chunks = []

        while bytes_left > 1:
            # Choose a size for our chunk based on the above calculated floor and ceiling and append to our list of chunks sizes
            chunk_size = random.randrange(rough_chunk_floor, rough_chunk_ceiling)
            self.chunks.append(chunk_size)

            # We need to not go below zero for a chunk size ..
            if bytes_left - chunk_size < 0:
                break

            # Reduce bytes_left by a our chunk size
            bytes_left = bytes_left - chunk_size

        # If we have any bytes left over, append to our list of chunk sizes
        if bytes_left:
            self.chunks.append(bytes_left)

        log.debug(f"Chunks obtained: {self.chunks}")

    def shatter(self):
        """Split up file then construct and write shards."""
        log.info(f"Reading chunks from {self.file.name}")
        with open(self.file.name, 'rb') as file:
            for chunk in self.chunks:
                log.debug(f"Reading chunk {chunk}")
                data = file.read(chunk)
                self.shard_data.append(data)

                self.shards.append({
                    'filename': self._random_string(),
                })

        # log.debug(self.shard_data)

        i = 0
        for shard in self.shards:
            if i > 0:
                shard['prev_shard'] = self.shards[i - 1]['filename']

            if i < len(self.shards) - 1:
                shard['next_shard'] = self.shards[i + 1]['filename']

            i = i + 1

        log.debug(f"Shards: {self.shards}")

        log.info(f"Creating shards ...")
        i = 0
        for shard in self.shards:
            log.debug(f"Writing shard {shard['filename']}")
            file = open(shard['filename'], 'w+b')

            # Encrypt the directory using the hash of the file
            log.debug(json.dumps(shard).encode())
            encrypted_shard = self.fernet.encrypt(json.dumps(shard).encode())
            encrypted_shard = base64.urlsafe_b64decode(encrypted_shard)

            # Calculate encrypted directory length
            encrypted_shard_len = len(encrypted_shard)
            log.debug(f"Encrypted shard length (decimal): {encrypted_shard_len}")
            encrypted_shard_len = encrypted_shard_len.to_bytes(1, byteorder='little')
            log.debug(f"Encrypted shard length (bytes): {encrypted_shard_len}")

            # Write header (directory len, terminator, directory)
            file.write(encrypted_shard_len)
            file.write(b'\x00')
            file.write(encrypted_shard)

            # Encrypt and write data
            encrypted_data = self.fernet.encrypt(self.shard_data[i])
            encrypted_data = base64.urlsafe_b64decode(encrypted_data)
            file.write(encrypted_data)

            file.close()

            i = i + 1

    def _random_string(self):
        length = random.randint(6, 16)
        return ''.join(random.choices(string.ascii_letters, k=length))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'action',
        choices=['shatter', 'reconstruct'],
        metavar='action',
        help="'shatter' to shatter a file; 'reconstruct' to reconstruct a file from a shard"
    )
    parser.add_argument('file', type=argparse.FileType('r'), help='File to shatter or shard file to reconstruct')

    parser.add_argument('-v', '--verbose', help='Print debug info', action='store_true',)

    shatter_group = parser.add_argument_group('SHATTER options')
    shatter_group.add_argument('-d', '--dir', help='Root directory to scatter shards in (default cwd)')
    shatter_group.add_argument('-S', '--shards', type=int, default=10, help='Rough number of shards to generate (int; Default 10)')
    shatter_group.add_argument(
        '-F', '--fuzzrange',
        type=float,
        choices=float_range(0.01, 1.0, 0.01),
        help="""
            Percentage of shard size ceiling to calculate for floor range. (float; 0.01-1.00; Default 0.5)
            Lower will result in more random file sizes.
            1 will split exactly on the equal division of file size by number of shards.
        """.lstrip(),
        default=0.5
    )

    reconstruct_group = parser.add_argument_group('RECONSTRUCT options')
    reconstruct_group.add_argument('-o', '--outfile', help='File to write when shards are reconstructed', type=argparse.FileType('w'))

    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.action and args.file:
        password = getpass.getpass()

        if args.action == 'shatter':
            confirm_password = getpass.getpass('Confirm Password:')
            if password != confirm_password:
                log.error("Passwords do not match")
                exit()

        key = key_from_password(password.encode())

    if args.action == 'shatter':
        file = Shatter(args.file, key, shards=args.shards, fuzz_range=args.fuzzrange)
    elif args.action == 'reconstruct':
        file = Reconstruct(args.file, args.outfile, key)
